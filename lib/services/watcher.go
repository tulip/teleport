/*
Copyright 2019 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or collectoried.
See the License for the specific language governing permissions and
limitations under the License.
*/

package services

import (
	"context"
	"sync"
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/pborman/uuid"
	"github.com/sirupsen/logrus"
)

// resourceCollector is a generic interface for maintaining an up-to-date view
// of a resource set being monitored. Used in conjunction with resourceWatcher.
type resourceCollector interface {
	// WatchKinds specifies the resource kinds to watch.
	WatchKinds() []types.WatchKind
	// notifyStale are called when the maximum acceptable staleness (if specified)
	// is exceeded.
	notifyStale(context.Context)
	// getResourcesAndUpdateCurrent is called when the resources should be
	// (re-)fetched directly.
	getResourcesAndUpdateCurrent(context.Context) error
	// processEventAndUpdateCurrent is called when a watcher event is received.
	processEventAndUpdateCurrent(context.Context, types.Event) error
}

// ResourceWatcherConfig configures resource watcher.
type ResourceWatcherConfig struct {
	// ParentContext is a parent context.
	ParentContext context.Context
	// Component is a component used in logs.
	Component string
	// Log is a logger.
	Log logrus.FieldLogger
	// RetryPeriod is a retry period on failed watchers.
	RetryPeriod time.Duration
	// RefetchPeriod is a period after which to explicitly refetch the resources.
	// It is to protect against unexpected cache syncing issues.
	RefetchPeriod time.Duration
	// MaxStaleness is a maximum acceptable staleness for the locally maintained
	// resources, zero implies no staleness detection.
	MaxStaleness time.Duration
	// Clock is used to control time.
	Clock clockwork.Clock
	// Client is used to create new watchers.
	Client types.Events
}

// CheckAndSetDefaults checks parameters and sets default values.
func (cfg *ResourceWatcherConfig) CheckAndSetDefaults() error {
	if cfg.ParentContext == nil {
		cfg.ParentContext = context.Background()
	}
	if cfg.Component == "" {
		return trace.BadParameter("missing parameter Component")
	}
	if cfg.Log == nil {
		cfg.Log = logrus.StandardLogger()
	}
	if cfg.RetryPeriod == 0 {
		cfg.RetryPeriod = defaults.HighResPollingPeriod
	}
	if cfg.RefetchPeriod == 0 {
		cfg.RefetchPeriod = defaults.LowResPollingPeriod
	}
	if cfg.Clock == nil {
		cfg.Clock = clockwork.NewRealClock()
	}
	if cfg.Client == nil {
		return trace.BadParameter("missing parameter Client")
	}
	return nil
}

// newResourceWatcher returns a new instance of resourceWatcher.
// It is the caller's responsibility to verify the inputs' validity
// incl. cfg.CheckAndSetDefaults.
func newResourceWatcher(collector resourceCollector, cfg ResourceWatcherConfig) (*resourceWatcher, error) {
	retry, err := utils.NewLinear(utils.LinearConfig{
		Step: cfg.RetryPeriod / 10,
		Max:  cfg.RetryPeriod,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	ctx, cancel := context.WithCancel(cfg.ParentContext)
	p := &resourceWatcher{
		resourceCollector:     collector,
		ResourceWatcherConfig: cfg,
		ctx:                   ctx,
		cancel:                cancel,
		retry:                 retry,
		ResetC:                make(chan struct{}),
	}

	return p, nil
}

// resourceWatcher monitors additions, updates and deletions
// to a set of resources.
type resourceWatcher struct {
	resourceCollector
	ResourceWatcherConfig

	ctx    context.Context
	cancel context.CancelFunc

	// retry is used to manage backoff logic for watchers.
	retry utils.Retry

	// failureStartedAt records when the current sync failures were first
	// detected, zero if there are no failures present.
	failureStartedAt utils.TimeUnderMutex

	// ResetC is a channel to notify of internal watcher reset (used in tests).
	ResetC chan struct{}
}

// Done returns a channel that signals resource watcher closure.
func (p *resourceWatcher) Done() <-chan struct{} {
	return p.ctx.Done()
}

// Close closes resource watcher and cancels all the functions.
func (p *resourceWatcher) Close() {
	p.cancel()
}

// hasStaleView returns true when the local view has failed to be updated
// for longer than the MaxStaleness bound.
func (p *resourceWatcher) hasStaleView() bool {
	if p.MaxStaleness == 0 {
		return false
	}
	failStart := p.failureStartedAt.Get()
	if failStart.IsZero() {
		return false
	}
	return p.Clock.Since(failStart) > p.MaxStaleness
}

// RunWatchLoop runs a watch loop.
func (p *resourceWatcher) RunWatchLoop() {
	for {
		p.Log.WithField("retry", p.retry).Debug("Starting watch.")
		err := p.watch()
		if err != nil {
			p.Log.WithError(err).Warning("Restart watch on error.")
			if p.MaxStaleness != 0 {
				p.failureStartedAt.SetIfZero(p.Clock.Now())
			}
		}
		if p.hasStaleView() {
			failStart := p.failureStartedAt.Get()
			p.Log.Warningf("Maximum staleness %v exceeded: failure started at %v.", p.MaxStaleness, failStart)
			p.notifyStale(p.ctx)
		}
		select {
		case p.ResetC <- struct{}{}:
		default:
		}
		select {
		case <-p.retry.After():
			p.retry.Inc()
		case <-p.ctx.Done():
			p.Log.Debug("Closed, returning from watch loop.")
			return
		}
	}
}

// watch monitors new resource updates, maintains a local view and broadcasts
// notifications to connected agents.
func (p *resourceWatcher) watch() error {
	watcher, err := p.Client.NewWatcher(p.ctx, types.Watch{
		Name:            p.Component,
		MetricComponent: p.Component,
		Kinds:           p.WatchKinds(),
	})
	if err != nil {
		return trace.Wrap(err)
	}
	defer watcher.Close()
	refetchC := time.After(p.RefetchPeriod)

	// before fetch, make sure watcher is synced by receiving init event,
	// to avoid the scenario:
	// 1. Cache process:   w = NewWatcher()
	// 2. Cache process:   c.fetch()
	// 3. Backend process: addItem()
	// 4. Cache process:   <- w.Events()
	//
	// If there is a way that NewWatcher() on line 1 could
	// return without subscription established first,
	// Code line 3 could execute and line 4 could miss event,
	// wrapping up with out of sync replica.
	// To avoid this, before doing fetch,
	// cache process makes sure the connection is established
	// by receiving init event first.
	select {
	case <-watcher.Done():
		return trace.ConnectionProblem(watcher.Error(), "watcher is closed")
	case <-refetchC:
		p.Log.Debug("Triggering scheduled refetch.")
		return nil
	case <-p.ctx.Done():
		return trace.ConnectionProblem(p.ctx.Err(), "context is closing")
	case event := <-watcher.Events():
		if event.Type != types.OpInit {
			return trace.BadParameter("expected init event, got %v instead", event.Type)
		}
	}

	if err := p.getResourcesAndUpdateCurrent(p.ctx); err != nil {
		return trace.Wrap(err)
	}
	p.retry.Reset()
	if p.MaxStaleness != 0 {
		p.failureStartedAt.Clear()
	}

	for {
		select {
		case <-watcher.Done():
			return trace.ConnectionProblem(watcher.Error(), "watcher is closed")
		case <-refetchC:
			p.Log.Debug("Triggering scheduled refetch.")
			return nil
		case <-p.ctx.Done():
			return trace.ConnectionProblem(p.ctx.Err(), "context is closing")
		case event := <-watcher.Events():
			if err := p.processEventAndUpdateCurrent(p.ctx, event); err != nil {
				return trace.Wrap(err)
			}
		}
	}
}

// ProxyWatcherConfig is a ProxyWatcher configuration.
type ProxyWatcherConfig struct {
	ResourceWatcherConfig
	// ProxyGetter is used to directly fetch the list of active proxies.
	ProxyGetter
	// ProxiesC is a channel used to report the current proxy set. It receives
	// a fresh list at startup and subsequently a list of all known proxies
	// whenever an addition or deletion is detected.
	ProxiesC chan []types.Server
}

// CheckAndSetDefaults checks parameters and sets default values.
func (cfg *ProxyWatcherConfig) CheckAndSetDefaults() error {
	if err := cfg.ResourceWatcherConfig.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if cfg.ProxyGetter == nil {
		getter, ok := cfg.Client.(ProxyGetter)
		if !ok {
			return trace.BadParameter("missing parameter ProxyGetter and Client not usable as ProxyGetter")
		}
		cfg.ProxyGetter = getter
	}
	if cfg.ProxiesC == nil {
		cfg.ProxiesC = make(chan []types.Server)
	}
	return nil
}

// NewProxyWatcher returns a new instance of ProxyWatcher.
func NewProxyWatcher(cfg ProxyWatcherConfig) (*ProxyWatcher, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	collector := &proxyCollector{
		ProxyWatcherConfig: cfg,
	}
	watcher, err := newResourceWatcher(collector, cfg.ResourceWatcherConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &ProxyWatcher{watcher, collector}, nil
}

// ProxyWatcher is built on top of resourceWatcher to monitor additions
// and deletions to the set of proxies.
type ProxyWatcher struct {
	*resourceWatcher
	*proxyCollector
}

// proxyCollector accompanies resourceWatcher when monitoring proxies.
type proxyCollector struct {
	ProxyWatcherConfig
	// current holds a map of the currently known proxies (keyed by server name,
	// RWMutex protected).
	current map[string]types.Server
	rw      sync.RWMutex
}

// GetCurrent returns the currently stored proxies.
func (p *proxyCollector) GetCurrent() []types.Server {
	p.rw.RLock()
	defer p.rw.RUnlock()
	return serverMapValues(p.current)
}

// WatchKinds specifies the resource kinds to watch.
func (p *proxyCollector) WatchKinds() []types.WatchKind {
	return []types.WatchKind{
		{
			Kind: types.KindProxy,
		},
	}
}

func (p *proxyCollector) notifyStale(context.Context) {}

// getResourcesAndUpdateCurrent is called when the resources should be
// (re-)fetched directly.
func (p *proxyCollector) getResourcesAndUpdateCurrent(ctx context.Context) error {
	proxies, err := p.GetProxies()
	if err != nil {
		return trace.Wrap(err)
	}
	if len(proxies) == 0 {
		// At least one proxy ought to exist.
		return trace.NotFound("empty proxy list")
	}
	newCurrent := make(map[string]types.Server, len(proxies))
	for _, proxy := range proxies {
		newCurrent[proxy.GetName()] = proxy
	}
	p.rw.Lock()
	defer p.rw.Unlock()
	p.current = newCurrent
	return trace.Wrap(p.broadcastUpdate(ctx))
}

// processEventAndUpdateCurrent is called when a watcher event is received.
func (p *proxyCollector) processEventAndUpdateCurrent(ctx context.Context, event types.Event) error {
	if event.Resource == nil || event.Resource.GetKind() != types.KindProxy {
		p.Log.Warningf("Unexpected event: %v.", event)
		return nil
	}

	p.rw.Lock()
	defer p.rw.Unlock()

	switch event.Type {
	case types.OpDelete:
		delete(p.current, event.Resource.GetName())
		// Always broadcast when a proxy is deleted.
		return trace.Wrap(p.broadcastUpdate(ctx))
	case types.OpPut:
		server, ok := event.Resource.(types.Server)
		if !ok {
			p.Log.Warningf("Unexpected type %T.", event.Resource)
			return nil
		}
		_, known := p.current[server.GetName()]
		p.current[server.GetName()] = server
		// Broadcast only creation of new proxies (not known before).
		if !known {
			return trace.Wrap(p.broadcastUpdate(ctx))
		}
		return nil
	default:
		p.Log.Warningf("Skipping unsupported event type %v.", event.Type)
		return nil
	}
}

// broadcastUpdate broadcasts information about updating the proxy set.
func (p *proxyCollector) broadcastUpdate(ctx context.Context) error {
	names := make([]string, 0, len(p.current))
	for k := range p.current {
		names = append(names, k)
	}
	p.Log.Debugf("List of known proxies updated: %q.", names)

	select {
	case p.ProxiesC <- serverMapValues(p.current):
	case <-ctx.Done():
		return trace.ConnectionProblem(ctx.Err(), "context is closing")
	}
	return nil
}

func serverMapValues(serverMap map[string]types.Server) []types.Server {
	servers := make([]types.Server, 0, len(serverMap))
	for _, server := range serverMap {
		servers = append(servers, server)
	}
	return servers
}

// LockWatcherConfig is a LockWatcher configuration.
type LockWatcherConfig struct {
	ResourceWatcherConfig
	LockGetter
}

// CheckAndSetDefaults checks parameters and sets default values.
func (cfg *LockWatcherConfig) CheckAndSetDefaults() error {
	if err := cfg.ResourceWatcherConfig.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if cfg.MaxStaleness == 0 {
		cfg.MaxStaleness = defaults.LockMaxStaleness
	}
	if cfg.LockGetter == nil {
		getter, ok := cfg.Client.(LockGetter)
		if !ok {
			return trace.BadParameter("missing parameter LockGetter and Client not usable as LockGetter")
		}
		cfg.LockGetter = getter
	}
	return nil
}

// NewLockWatcher returns a new instance of LockWatcher.
func NewLockWatcher(cfg LockWatcherConfig) (*LockWatcher, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	collector := &lockCollector{
		LockWatcherConfig: cfg,
	}
	watcher, err := newResourceWatcher(collector, cfg.ResourceWatcherConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &LockWatcher{watcher, collector}, nil
}

// LockWatcher is built on top of resourceWatcher to monitor changes to locks.
type LockWatcher struct {
	*resourceWatcher
	*lockCollector
}

// lockCollector accompanies resourceWatcher when monitoring locks.
type lockCollector struct {
	LockWatcherConfig
	// current holds a map of the currently known locks (keyed by lock name,
	// RWMutex protected).
	current    map[string]types.Lock
	currentErr error
	rw         sync.RWMutex
	// subscriptionMap is a map of subscribers to broadcast the changes to.
	subscriptionMap sync.Map
}

// Subscribe is used to subscribe to the lock updates.
func (p *lockCollector) Subscribe(targets []types.LockTarget) (LockWatcherSubscription, error) {
	sub := LockWatcherSubscription{
		collector:    p,
		ID:           uuid.New(),
		LockInForceC: make(chan types.Lock),
		StaleC:       make(chan struct{}),
		Targets:      targets,
	}
	p.subscriptionMap.Store(sub.ID, sub)
	return sub, nil
}

// LockWatcherSubscription holds channels to receive the lock updates on.
type LockWatcherSubscription struct {
	// collector that issued this subscription.
	collector *lockCollector
	// ID is a unique identifier of this subscription in the collector's
	// subscription map.
	ID string
	// LockInForceC is a channel to receive the lock updates on.
	LockInForceC chan types.Lock
	// StaleC is pinged when the collector's lock view becomes stale.
	StaleC chan struct{}
	// Targets can be used to filter the received lock updates.
	Targets []types.LockTarget
}

// Unsubscribe removes this subscription from the collector's subscription map
// and allows its resources to be deallocated.
func (s LockWatcherSubscription) Unsubscribe() {
	s.collector.subscriptionMap.Delete(s.ID)
}

// GetLocksInForce returns the stored locks in force.
func (p *lockCollector) GetLockInForce(targets ...types.LockTarget) (types.Lock, error) {
	p.rw.RLock()
	defer p.rw.RUnlock()
	if p.currentErr != nil {
		return nil, p.currentErr
	}
	return lockInForce(p.Clock, p.current, targets), nil
}

// WatchKinds specifies the resource kinds to watch.
func (p *lockCollector) WatchKinds() []types.WatchKind {
	return []types.WatchKind{
		{
			Kind: types.KindLock,
		},
	}
}

// notifyStale is called when the maximum acceptable staleness (if specified)
// is exceeded.
func (p *lockCollector) notifyStale(ctx context.Context) {
	p.subscriptionMap.Range(func(key, value interface{}) bool {
		s, ok := value.(LockWatcherSubscription)
		if !ok {
			p.Log.Warningf("Unexpected subscription type %T.", value)
			return true
		}
		select {
		case s.StaleC <- struct{}{}:
		case <-ctx.Done():
			return false
		}
		return true
	})

	if p.currentErr != nil {
		return
	}
	p.rw.Lock()
	defer p.rw.Unlock()
	p.current = nil
	p.currentErr = trace.ConnectionProblem(nil, "maximum staleness %v exceeded", p.MaxStaleness)
}

// getResourcesAndUpdateCurrent is called when the resources should be
// (re-)fetched directly.
func (p *lockCollector) getResourcesAndUpdateCurrent(ctx context.Context) error {
	locks, err := p.GetLocks(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	newCurrent := make(map[string]types.Lock, len(locks))
	for _, lock := range locks {
		newCurrent[lock.GetName()] = lock
	}

	p.rw.Lock()
	defer p.rw.Unlock()
	p.current = newCurrent
	p.currentErr = nil
	return trace.Wrap(p.broadcastUpdate(ctx))
}

// processEventAndUpdateCurrent is called when a watcher event is received.
func (p *lockCollector) processEventAndUpdateCurrent(ctx context.Context, event types.Event) error {
	if event.Resource == nil || event.Resource.GetKind() != types.KindLock {
		p.Log.Warningf("Unexpected event: %v.", event)
		return nil
	}

	p.rw.Lock()
	defer p.rw.Unlock()

	switch event.Type {
	case types.OpDelete:
		delete(p.current, event.Resource.GetName())
		// Always broadcast when a lock is deleted.
		return trace.Wrap(p.broadcastUpdate(ctx))
	case types.OpPut:
		lock, ok := event.Resource.(types.Lock)
		if !ok {
			p.Log.Warningf("Unexpected resource type %T.", event.Resource)
			return nil
		}
		p.current[lock.GetName()] = lock
		return trace.Wrap(p.broadcastUpdate(ctx))
	default:
		p.Log.Warningf("Skipping unsupported event type %v.", event.Type)
		return nil
	}
}

// broadcastUpdate broadcasts information about updating the proxy set.
func (p *lockCollector) broadcastUpdate(ctx context.Context) error {
	var err error
	p.subscriptionMap.Range(func(key, value interface{}) bool {
		s, ok := value.(LockWatcherSubscription)
		if !ok {
			p.Log.Warningf("Unexpected subscription type %T.", value)
			return true
		}
		lock := lockInForce(p.Clock, p.current, s.Targets)
		if lock == nil {
			return true
		}
		select {
		case s.LockInForceC <- lock:
		case <-ctx.Done():
			err = trace.ConnectionProblem(ctx.Err(), "context is closing")
			return false
		}
		return true
	})
	return err
}

// lockInForce returns an active lock matching the targets from the lockMap,
// nil if not found.
func lockInForce(clock clockwork.Clock, lockMap map[string]types.Lock, targets []types.LockTarget) types.Lock {
	for _, lock := range lockMap {
		if !lock.IsInForce(clock) {
			continue
		}
		if len(targets) == 0 {
			return lock
		}
		for _, target := range targets {
			if target.Match(lock) {
				return lock
			}
		}
	}
	return nil
}

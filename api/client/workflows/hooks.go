/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package workflows

import (
	"context"
	"log"
	"sync"

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/types"

	"github.com/gravitational/trace"
)

type Server struct {
	Client *client.Client
	Router *Router
	Filter *types.AccessRequestFilter
}

func (s *Server) Run(ctx context.Context) error {
	watcher, err := s.Client.NewWatcher(ctx,
		types.Watch{
			Kinds: []types.WatchKind{{
				Kind:   types.KindAccessRequest,
				Filter: s.Filter.IntoMap(),
			}},
		},
	)
	if err != nil {
		return trace.Wrap(err)
	}
	defer watcher.Close()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-watcher.Done():
			return watcher.Error()
		case event := <-watcher.Events():
			if err := s.handleEvent(ctx, event); err != nil {
				return trace.Wrap(err)
			}
		}
	}
}

func (s *Server) handleEvent(ctx context.Context, event types.Event) error {
	log.Printf("Received event: %v", event)

	// Ignore non-put events
	if event.Type != types.OpPut {
		return nil
	}

	request, ok := event.Resource.(types.AccessRequest)
	if !ok {
		return trace.Errorf("Received unexpected Resource type %T", request)
	}

	requestKeys, err := s.keysFromRequest(request)
	if err != nil {
		return trace.Wrap(err)
	}
	log.Printf("requestKeys: %v\n", requestKeys)

	// Range over router entries to match the request to a route.
	// Use the first match to handle the request.
	for _, entry := range s.Router.entries {
		log.Printf("entry.Keys: %v\n", entry.Keys)
		if entry.Match(requestKeys) {
			updateParams, err := entry.Handler(ctx, request)
			if err != nil {
				return trace.Wrap(err)
			}
			if err = s.Client.SetAccessRequestState(ctx, updateParams); err != nil {
				return trace.Wrap(err)
			}
			return nil
		}
	}
	return nil
}

func (s *Server) keysFromRequest(req types.AccessRequest) ([]CompositeKey, error) {
	keys := []CompositeKey{
		MatchUserID(req.GetUser()),
		MatchRequestState(req.GetState()),
		MatchRequestID(req.GetName()),
	}

	user, err := s.Client.GetUser(req.GetUser(), false)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	keys = append(keys, KeysFromTraits(user.GetTraits())...)
	keys = append(keys, KeysFromLabels(user.GetMetadata().Labels)...)

	return keys, nil
}

type Router struct {
	entriesMux sync.Mutex
	entries    []Route
}

type Route struct {
	Handler Handler
	Keys    []CompositeKey
}

func (r *Route) Match(reqKeys []CompositeKey) bool {
OUTER:
	for _, k := range r.Keys {
		for _, matchKey := range reqKeys {
			if k.Match(matchKey) {
				continue OUTER
			}
		}
		return false
	}
	return true
}

type Handler func(ctx context.Context, req types.AccessRequest) (updateParams types.AccessRequestUpdate, err error)

// Entries should be added in order of priority due to overlap between routes.
func (r *Router) HandleFunc(handle Handler, keys ...CompositeKey) {
	r.entriesMux.Lock()
	defer r.entriesMux.Unlock()
	r.entries = append(r.entries, Route{Handler: handle, Keys: keys})
}

type CompositeKey struct {
	Kind  CompositeKeyKind
	Key   string
	Value string
}

type CompositeKeyKind string

const (
	FilterKind    CompositeKeyKind = "filter"
	UserLabelKind CompositeKeyKind = "label"
	UserTraitKind CompositeKeyKind = "trait"
)

func (k CompositeKey) Match(matchKey CompositeKey) bool {
	return k == matchKey
}

func MatchUserTrait(key string, value string) CompositeKey {
	return CompositeKey{
		Kind:  UserTraitKind,
		Key:   key,
		Value: value,
	}
}

func KeysFromTraits(traits map[string][]string) []CompositeKey {
	keys := []CompositeKey{}
	for key, values := range traits {
		for _, value := range values {
			keys = append(keys, MatchUserTrait(key, value))
		}
	}
	log.Printf("traitKeys: %v\n", keys)
	return keys
}

func MatchUserLabel(key string, value string) CompositeKey {
	return CompositeKey{
		Kind:  UserLabelKind,
		Key:   key,
		Value: value,
	}
}

func KeysFromLabels(labels map[string]string) []CompositeKey {
	keys := []CompositeKey{}
	for key, value := range labels {
		keys = append(keys, MatchUserLabel(key, value))
	}
	log.Printf("labelKeys: %v\n", keys)
	return keys
}

func MatchRequestState(state types.RequestState) CompositeKey {
	return CompositeKey{
		Kind:  FilterKind,
		Key:   "state",
		Value: state.String(),
	}
}

func MatchRequestID(id string) CompositeKey {
	return CompositeKey{
		Kind:  FilterKind,
		Key:   "req_id",
		Value: id,
	}
}

func MatchUserID(id string) CompositeKey {
	return CompositeKey{
		Kind:  FilterKind,
		Key:   "user_id",
		Value: id,
	}
}

func KeysFromFilter(fitler types.AccessRequestFilter) []CompositeKey {
	return []CompositeKey{}
}

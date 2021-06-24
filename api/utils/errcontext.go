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

package utils

import (
	"context"
	"time"
)

// ErrContext provides an instantly cancelled context with a user specified error.
type ErrContext struct {
	done <-chan struct{}
	err  error
}

func NewErrContext(err error) *ErrContext {
	c := make(chan struct{})
	close(c)

	return &ErrContext{
		done: c,
		err:  err,
	}
}

func (e *ErrContext) Deadline() (deadline time.Time, ok bool) {
	return time.Now(), true
}

func (e *ErrContext) Done() <-chan struct{} {
	return e.done
}

func (e *ErrContext) Err() error {
	return e.err
}

func (e *ErrContext) Value(key interface{}) interface{} {
	return nil
}

// CancelWithErrContext behaves like context.CancelContext but allows a user provided error.
type CancelWithErrContext struct {
	parent context.Context
	done   chan struct{}
	err    error
}

func NewCancelWithErrContext(parent context.Context) (*CancelWithErrContext, func(error)) {
	ctx := &CancelWithErrContext{
		parent: parent,
		done:   make(chan struct{}),
		err:    nil,
	}

	go func() {
		select {
		case <-ctx.parent.Done():
			ctx.err = ctx.parent.Err()
			close(ctx.done)
		case <-ctx.done:
		}
	}()

	cancel := func(err error) {
		ctx.err = err
		close(ctx.done)
	}

	return ctx, cancel
}

func (e *CancelWithErrContext) Deadline() (deadline time.Time, ok bool) {
	return time.Now(), true
}

func (e *CancelWithErrContext) Done() <-chan struct{} {
	return e.done
}

func (e *CancelWithErrContext) Err() error {
	return e.err
}

func (e *CancelWithErrContext) Value(key interface{}) interface{} {
	return nil
}

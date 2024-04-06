/*
 * This file is part of the KubeVirt project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright The KubeVirt Authors
 *
 */

package cache

import (
	"fmt"
	"sync"
	"time"
)

type TimeDefinedCache[T any] struct {
	minRefreshDuration time.Duration
	lastRefresh        time.Time
	savedValueSet      bool
	savedValue         T
	reCalcFunc         func() (T, error)
	valueLock          *sync.RWMutex
}

// NewTimeDefinedCache creates a new cache that will refresh the value every minRefreshDuration. If the value is requested
// before the minRefreshDuration has passed, the cached value will be returned. If minRefreshDuration is zero, the value will always be
// recalculated.
// In addition, a Set() can be used to explicitly set the value.
// If useValueLock is set to true, the value will be locked when being set. If the cache won't be used concurrently, it's safe
// to set this to false.
func NewTimeDefinedCache[T any](minRefreshDuration time.Duration, useValueLock bool, reCalcFunc func() (T, error)) (*TimeDefinedCache[T], error) {
	if reCalcFunc == nil {
		return nil, fmt.Errorf("re-calculation function is not set")
	}

	t := &TimeDefinedCache[T]{
		minRefreshDuration: minRefreshDuration,
		reCalcFunc:         reCalcFunc,
	}

	if useValueLock {
		t.valueLock = &sync.RWMutex{}
	}

	return t, nil
}

func (t *TimeDefinedCache[T]) Get() (T, error) {
	if t.savedValueSet && t.minRefreshDuration.Nanoseconds() != 0 && time.Since(t.lastRefresh) <= t.minRefreshDuration {
		if t.valueLock != nil {
			t.valueLock.RLock()
			defer t.valueLock.RUnlock()
		}
		return t.savedValue, nil
	}

	if t.valueLock != nil {
		t.valueLock.Lock()
		defer t.valueLock.Unlock()
	}

	value, err := t.reCalcFunc()
	if err != nil {
		return t.savedValue, err
	}

	t.setWithoutLock(value)

	return t.savedValue, nil
}

func (t *TimeDefinedCache[T]) Set(value T) {
	if t.valueLock != nil {
		t.valueLock.Lock()
		defer t.valueLock.Unlock()
	}

	t.setWithoutLock(value)
}

func (t *TimeDefinedCache[T]) setWithoutLock(value T) {
	t.savedValue = value
	t.savedValueSet = true
	t.lastRefresh = time.Now()
}

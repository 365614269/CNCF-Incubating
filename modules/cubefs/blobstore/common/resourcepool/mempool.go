// Copyright 2022 The CubeFS Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

package resourcepool

import (
	"errors"
	"sort"
)

// ErrNoSuitableSizeClass no suitable pool of size
var ErrNoSuitableSizeClass = errors.New("no suitable size class")

// zero bytes, high performance at the 16KB, see more in the benchmark:
// BenchmarkZero/4MB-16KB-4                   13338             88378 ns/op
// BenchmarkZero/8MB-16KB-4                    6670            183987 ns/op
// BenchmarkZero/16MB-16KB-4                   1926            590422 ns/op
const zeroLen = 1 << 14

var zero = make([]byte, zeroLen)

// MemPool reused buffer pool
type MemPool struct {
	pool     []Pool
	poolSize []int
}

// Status memory pools status
type Status []PoolStatus

// PoolStatus status of the pool
type PoolStatus struct {
	Size     int `json:"size"`
	Capacity int `json:"capacity"`
	Running  int `json:"running"`
	Idle     int `json:"idle"`
}

// NewMemPool returns a MemPool within chan pool
func NewMemPool(sizeClasses map[int]int) *MemPool {
	return NewMemPoolWith(sizeClasses, func(size, capacity int) Pool {
		return NewChanPool(func() []byte {
			return make([]byte, size)
		}, capacity)
	})
}

// NewMemPoolWith new MemPool with size-class and self-defined pool
func NewMemPoolWith(sizeClasses map[int]int, newPool func(size, capacity int) Pool) *MemPool {
	pool := make([]Pool, 0, len(sizeClasses))
	poolSize := make([]int, 0, len(sizeClasses))
	for sizeClass := range sizeClasses {
		if sizeClass > 0 {
			poolSize = append(poolSize, sizeClass)
		}
	}

	sort.Ints(poolSize)
	for _, sizeClass := range poolSize {
		pool = append(pool, newPool(sizeClass, sizeClasses[sizeClass]))
	}

	return &MemPool{
		pool:     pool,
		poolSize: poolSize,
	}
}

// Get return a suitable buffer
func (p *MemPool) Get(size int) ([]byte, error) {
	for idx, ps := range p.poolSize {
		if size <= ps {
			buf, err := p.pool[idx].Get()
			if err != nil {
				return nil, err
			}
			buff := buf.([]byte)
			return buff[:size], nil
		}
	}

	return nil, ErrNoSuitableSizeClass
}

// Alloc return a buffer, make a new if oversize
func (p *MemPool) Alloc(size int) ([]byte, error) {
	buf, err := p.Get(size)
	if err == ErrNoSuitableSizeClass {
		return make([]byte, size), nil
	}

	return buf, err
}

// Put adds x to the pool, appropriately resize
func (p *MemPool) Put(b []byte) error {
	sizeClass := cap(b)
	b = b[0:sizeClass]
	for ii := len(p.poolSize) - 1; ii >= 0; ii-- {
		if sizeClass >= p.poolSize[ii] {
			b = b[0:p.poolSize[ii]]
			p.pool[ii].Put(b)
			return nil
		}
	}

	return ErrNoSuitableSizeClass
}

// Zero clean up the buffer b to zero bytes
func (p *MemPool) Zero(b []byte) {
	Zero(b)
}

// Status returns status of memory pool
func (p *MemPool) Status() Status {
	st := make(Status, len(p.poolSize))
	for idx, size := range p.poolSize {
		pool := p.pool[idx]
		st[idx] = PoolStatus{
			Size:     size,
			Capacity: pool.Cap(),
			Running:  pool.Len(),
			Idle:     pool.Idle(),
		}
	}
	return st
}

// Zero clean up the buffer b to zero bytes
func Zero(b []byte) {
	for len(b) > 0 {
		n := copy(b, zero)
		b = b[n:]
	}
}

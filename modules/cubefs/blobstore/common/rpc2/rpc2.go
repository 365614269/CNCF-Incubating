// Copyright 2024 The CubeFS Authors.
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

package rpc2

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/cubefs/cubefs/blobstore/common/rpc2/transport"
	"github.com/cubefs/cubefs/blobstore/common/trace"
	"github.com/cubefs/cubefs/blobstore/util"
)

const (
	Version = 0
	Magic   = 0xee

	_headerCell = 4

	_maxCodecerSize = 16 << 20
)

var (
	errLimitedWrite = errors.New("rpc2: body should be limited")

	ErrServerClosed  = errors.New("rpc2: server closed")
	ErrLimitedWriter = errors.New("rpc2: request or response body must wrap with rpc2.LimitedWriter")
	ErrFrameHeader   = errors.New("rpc2: request or response header must be in independent frame")
	ErrFrameProtocol = errors.New("rpc2: undefined protocol frame")
	ErrConnLimited   = NewError(400, "ConnLimited", "rpc2: session or stream was limited")
	ErrConnNoAddress = NewError(400, "ConnNoAddress", "rpc2: lb client has no address")
)

type TransportConfig struct {
	Version           int           `json:"version"`
	KeepAliveDisabled bool          `json:"keepalive_disabled"`
	KeepAliveInterval util.Duration `json:"keepalive_interval"`
	KeepAliveTimeout  util.Duration `json:"keepalive_timeout"`
	MaxFrameSize      int           `json:"max_frame_size"`
	MaxReceiveBuffer  int           `json:"max_receive_buffer"`
	MaxStreamBuffer   int           `json:"max_stream_buffer"`
}

func (tc *TransportConfig) Transport() *transport.Config {
	if tc == nil {
		return nil
	}
	return &transport.Config{
		Version:           tc.Version,
		KeepAliveDisabled: tc.KeepAliveDisabled,
		KeepAliveInterval: tc.KeepAliveInterval.Duration,
		KeepAliveTimeout:  tc.KeepAliveTimeout.Duration,
		MaxFrameSize:      tc.MaxFrameSize,
		MaxReceiveBuffer:  tc.MaxReceiveBuffer,
		MaxStreamBuffer:   tc.MaxStreamBuffer,
	}
}

func DefaultTransportConfig() *TransportConfig {
	tc := transport.DefaultConfig()
	return &TransportConfig{
		Version:           2,
		KeepAliveDisabled: tc.KeepAliveDisabled,
		KeepAliveInterval: utilDuration(tc.KeepAliveInterval),
		KeepAliveTimeout:  utilDuration(tc.KeepAliveTimeout),
		MaxFrameSize:      tc.MaxFrameSize,
		MaxReceiveBuffer:  tc.MaxReceiveBuffer,
		MaxStreamBuffer:   tc.MaxStreamBuffer,
	}
}

type (
	Marshaler interface {
		Size() int
		Marshal() ([]byte, error)
		MarshalTo([]byte) (int, error)
	}
	Unmarshaler interface {
		Unmarshal([]byte) error
	}
	Readable interface {
		Readable() bool
	}
	Codec interface {
		Marshaler
		Unmarshaler
	}
)

var (
	_           Codec = (*AnyCodec[struct{}])(nil)
	NoParameter Codec = noneCodec{}
)

type noneCodec struct{}

func (noneCodec) Size() int                     { return 0 }
func (noneCodec) Marshal() ([]byte, error)      { return nil, nil }
func (noneCodec) MarshalTo([]byte) (int, error) { return 0, nil }
func (noneCodec) Unmarshal([]byte) error        { return nil }

type AnyCodec[T any] struct {
	Value T

	buff []byte
	err  error
}

func (m *AnyCodec[T]) Size() int                       { m.json(); return len(m.buff) }
func (m *AnyCodec[T]) Marshal() ([]byte, error)        { m.json(); return m.buff, m.err }
func (m *AnyCodec[T]) MarshalTo(b []byte) (int, error) { m.json(); return copy(b, m.buff), m.err }
func (m *AnyCodec[T]) Unmarshal(b []byte) error        { return json.Unmarshal(b, &m.Value) }
func (m *AnyCodec[T]) Readable() bool                  { return true }
func (m *AnyCodec[T]) json() {
	if m.buff != nil || m.err != nil {
		return
	}
	m.buff, m.err = json.Marshal(m.Value)
}

type Body interface {
	io.Reader
	io.WriterTo
	io.Closer
}

var NoBody Body = noBody{}

type noBody struct{}

func (noBody) Read([]byte) (int, error)         { return 0, io.EOF }
func (noBody) Close() error                     { return nil }
func (noBody) WriteTo(io.Writer) (int64, error) { return 0, nil }

type nopBody struct {
	io.ReadCloser
}

func (nopBody) WriteTo(io.Writer) (int64, error) {
	panic("rpc2: should not call WriteTo in client request")
}

func clientNopBody(rc io.ReadCloser) Body {
	return nopBody{rc}
}

var codecPool = sync.Pool{
	New: func() any { return bytes.NewBuffer(nil) },
}

type codecReadWriter struct {
	once        sync.Once
	reader      io.Reader
	marshaler   Marshaler
	remain      int
	unmarshaler Unmarshaler
	recv        int
	withcell    bool
	cell        headerCell
	cache       *bytes.Buffer
}

func (c *codecReadWriter) Size() int {
	if c.marshaler != nil {
		return c.marshaler.Size()
	}
	panic("rpc2: codec reader should not call Size()")
}

// Read reader marshal to
func (c *codecReadWriter) Read(p []byte) (n int, err error) {
	n, err = 0, io.EOF
	c.once.Do(func() {
		size := c.marshaler.Size()
		if size > _maxCodecerSize {
			err = ErrFrameHeader
			return
		}
		var nn int
		if c.withcell {
			if len(p) < len(c.cell) {
				err = io.ErrShortBuffer
				return
			}
			nn = copy(p, c.cell[:])
			n += nn
			p = p[nn:]
			c.withcell = false
		}

		if len(p) >= size {
			nn, err = c.marshaler.MarshalTo(p)
			n += nn
			return
		}

		cache := codecPool.Get().(*bytes.Buffer)
		cache.Reset()
		cache.Grow(size)
		cache.ReadFrom(util.DiscardReader(size))

		buff := cache.Bytes()
		nn, err = c.marshaler.MarshalTo(buff)
		if err != nil {
			codecPool.Put(cache)
			return
		}
		if size != nn {
			codecPool.Put(cache)
			err = io.ErrShortWrite
			return
		}
		c.reader = bytes.NewReader(buff)
		c.remain = size
		c.cache = cache
	})
	if c.reader != nil {
		n, err = c.reader.Read(p)
		c.remain -= n
		if c.remain <= 0 && c.cache != nil {
			codecPool.Put(c.cache)
			c.cache = nil
		}
	}
	return
}

func (c *codecReadWriter) Write(p []byte) (n int, err error) {
	n, err = 0, nil
	if c.recv > _maxCodecerSize {
		err = ErrFrameHeader
		return
	}

	if c.cache == nil && len(p) >= c.recv {
		c.once.Do(func() {
			if err = c.unmarshaler.Unmarshal(p); err == nil {
				n = len(p)
				c.recv -= n
			}
		})
		return
	}

	if c.cache == nil {
		c.cache = codecPool.Get().(*bytes.Buffer)
		c.cache.Reset()
	}

	n = len(p)
	if n > c.recv {
		n = c.recv
	}
	c.cache.Write(p[:n])
	c.recv -= n

	if c.recv <= 0 {
		c.once.Do(func() {
			err = c.unmarshaler.Unmarshal(c.cache.Bytes())
			codecPool.Put(c.cache)
			c.cache = nil
		})
	}
	return
}

func Codec2Reader(m Marshaler) io.Reader { return &codecReadWriter{marshaler: m} }
func Codec2Writer(m Unmarshaler, size int) io.Writer {
	return &codecReadWriter{unmarshaler: m, recv: size}
}

func codec2CellReader(cell headerCell, m Marshaler) io.Reader {
	return &codecReadWriter{marshaler: m, withcell: true, cell: cell}
}

// LimitedWriter wrap Body with WriteTo
type LimitedWriter struct {
	w io.Writer
	a int64
	n int64
}

func LimitWriter(w io.Writer, limit int64) io.Writer {
	return &LimitedWriter{w: w, a: limit, n: limit}
}

func (lw *LimitedWriter) Write(p []byte) (int, error) {
	if lw.n <= 0 {
		return 0, errLimitedWrite
	}
	if lw.n < int64(len(p)) {
		p = p[:lw.n]
	}
	n, err := lw.w.Write(p)
	lw.n -= int64(n)
	return n, err
}

func getSpan(ctx context.Context) trace.Span {
	return trace.SpanFromContextSafe(ctx)
}

func ContextWithTrace(ctx context.Context) context.Context {
	if span := trace.SpanFromContext(ctx); span == nil {
		_, ctx = trace.StartSpanFromContext(ctx, "")
	}
	return ctx
}

type headerCell [_headerCell]byte

func (h *headerCell) Set(n int) {
	binary.LittleEndian.PutUint32((*h)[:], uint32(n))
}

func (h *headerCell) Get() int {
	return int(binary.LittleEndian.Uint32((*h)[:]))
}

func (h *headerCell) Write(p []byte) (int, error) {
	_ = p[3]
	copy((*h)[:], p)
	return _headerCell, nil
}

func beforeContextDeadline(ctx context.Context, t time.Time) time.Time {
	d, ok := ctx.Deadline()
	if !ok {
		return t
	}
	return latestTime(t, d)
}

func latestTime(t time.Time, others ...time.Time) time.Time {
	for _, u := range others {
		if u.IsZero() {
			continue
		}
		if t.IsZero() || u.Before(t) {
			t = u
		}
	}
	return t
}

func utilDuration(t time.Duration) util.Duration {
	return util.Duration{Duration: t}
}

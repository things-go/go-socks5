package socks5

import (
	"sync"
)

// A BufferPool is an interface for getting and returning temporary
// byte slices for use by io.CopyBuffer.
type BufferPool interface {
	Get() []byte
	Put([]byte)
}

type pool struct {
	size int
	pool *sync.Pool
}

// NewPool new buffer pool for getting and returning temporary
// byte slices for use by io.CopyBuffer.
func NewPool(size int) BufferPool {
	return &pool{
		size,
		&sync.Pool{
			New: func() interface{} { return make([]byte, 0, size) }},
	}
}

// Get implement interface BufferPool
func (sf *pool) Get() []byte {
	return sf.pool.Get().([]byte)
}

// Put implement interface BufferPool
func (sf *pool) Put(b []byte) {
	if cap(b) != sf.size {
		panic("invalid buffer size that's put into leaky buffer")
	}
	sf.pool.Put(b[:0]) // nolint: staticcheck
}

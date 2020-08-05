package socks5

import (
	"sync"
)

type pool struct {
	size int
	pool *sync.Pool
}

func newPool(size int) *pool {
	return &pool{
		size,
		&sync.Pool{
			New: func() interface{} { return make([]byte, 0, size) }},
	}
}
func (sf *pool) Get() []byte {
	return sf.pool.Get().([]byte)
}

func (sf *pool) Put(b []byte) {
	if cap(b) != sf.size {
		panic("invalid buffer size that's put into leaky buffer")
	}
	sf.pool.Put(b[:0]) // nolint: staticcheck
}

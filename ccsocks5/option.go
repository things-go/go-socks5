package ccsocks5

import (
	"golang.org/x/net/proxy"

	"github.com/thinkgos/go-socks5/bufferpool"
)

// Option user's option of the client
type Option func(c *Client)

// WithAuth with user's auth
// default is nil,no UserPass
func WithAuth(auth *proxy.Auth) Option {
	return func(c *Client) {
		c.auth = auth
	}
}

// WithBufferPool with buffer pool
// default: 32k
func WithBufferPool(p bufferpool.BufPool) Option {
	return func(c *Client) {
		c.bufferPool = p
	}
}

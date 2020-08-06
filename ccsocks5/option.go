package ccsocks5

import (
	"context"
	"net"

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

// WithDial set custom dial
func WithDial(dial func(ctx context.Context, network, addr string) (net.Conn, error)) Option {
	return func(c *Client) {
		c.dial = dial
	}
}

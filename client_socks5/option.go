package client_socks5

import (
	"time"

	"golang.org/x/net/proxy"

	"github.com/thinkgos/go-socks5/bufferpool"
)

type Option func(c *Client)

func WithAuth(auth *proxy.Auth) Option {
	return func(c *Client) {
		c.auth = auth
	}
}

func WithBufferPool(p bufferpool.BufPool) Option {
	return func(c *Client) {
		c.bufferPool = p
	}
}

func WithKeepAlivePeriod(t time.Duration) Option {
	return func(c *Client) {
		c.KeepAlivePeriod = t
	}
}

func WithTCPDeadline(t time.Duration) Option {
	return func(c *Client) {
		c.TCPDeadline = t
	}
}

func WithUDPDeadline(t time.Duration) Option {
	return func(c *Client) {
		c.UDPDeadline = t
	}
}

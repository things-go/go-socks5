package client

import (
	"time"

	"golang.org/x/net/proxy"
)

type Option func(c *Client)

func WithAuth(auth *proxy.Auth) Option {
	return func(c *Client) {
		c.Auth = auth
	}
}

func WithTCPTimeout(t time.Duration) Option {
	return func(c *Client) {
		c.TCPTimeout = t
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

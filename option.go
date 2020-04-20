package socks5

import (
	"context"
	"net"
)

type Option func(s *Server)

// AuthMethods can be provided to implement custom authentication
// By default, "auth-less" mode is enabled.
// For password-based auth use UserPassAuthenticator.
func WithAuthMethods(authMethods []Authenticator) Option {
	return func(s *Server) {
		if len(authMethods) != 0 {
			s.authCustomMethods = make([]Authenticator, 0, len(authMethods))
			s.authCustomMethods = append(s.authCustomMethods, authMethods...)
		}
	}
}

// If provided, username/password authentication is enabled,
// by appending a UserPassAuthenticator to AuthMethods. If not provided,
// and AUthMethods is nil, then "auth-less" mode is enabled.
func WithCredential(cs CredentialStore) Option {
	return func(s *Server) {
		if cs != nil {
			s.credentials = cs
		}
	}
}

// resolver can be provided to do custom name resolution.
// Defaults to DNSResolver if not provided.
func WithResolver(res NameResolver) Option {
	return func(s *Server) {
		if res != nil {
			s.resolver = res
		}
	}
}

// rules is provided to enable custom logic around permitting
// various commands. If not provided, PermitAll is used.
func WithRule(rule RuleSet) Option {
	return func(s *Server) {
		if rule != nil {
			s.rules = rule
		}
	}
}

// rewriter can be used to transparently rewrite addresses.
// This is invoked before the RuleSet is invoked.
// Defaults to NoRewrite.
func WithRewriter(rew AddressRewriter) Option {
	return func(s *Server) {
		if rew != nil {
			s.rewriter = rew
		}
	}
}

// bindIP is used for bind or udp associate
func WithBindIP(ip net.IP) Option {
	return func(s *Server) {
		if len(ip) != 0 {
			s.bindIP = make(net.IP, 0, len(ip))
			s.bindIP = append(s.bindIP, ip)
		}
	}
}

// logger can be used to provide a custom log target.
// Defaults to ioutil.Discard.
func WithLogger(l Logger) Option {
	return func(s *Server) {
		if l != nil {
			s.logger = l
		}
	}
}

// Optional function for dialing out
func WithDial(dial func(ctx context.Context, network, addr string) (net.Conn, error)) Option {
	return func(s *Server) {
		if dial != nil {
			s.dial = dial
		}
	}
}

func WithGPool(pool GPool) Option {
	return func(s *Server) {
		if pool != nil {
			s.gPool = pool
		}
	}
}

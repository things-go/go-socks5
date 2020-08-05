package socks5

import (
	"context"

	"github.com/thinkgos/go-socks5/statute"
)

// RuleSet is used to provide custom rules to allow or prohibit actions
type RuleSet interface {
	Allow(ctx context.Context, req *Request) (context.Context, bool)
}

// PermitAll returns a RuleSet which allows all types of connections
func PermitAll() RuleSet {
	return &PermitCommand{true, true, true}
}

// PermitNone returns a RuleSet which disallows all types of connections
func PermitNone() RuleSet {
	return &PermitCommand{false, false, false}
}

// PermitCommand is an implementation of the RuleSet which
// enables filtering supported commands
type PermitCommand struct {
	EnableConnect   bool
	EnableBind      bool
	EnableAssociate bool
}

// Allow implement interface RuleSet
func (p *PermitCommand) Allow(ctx context.Context, req *Request) (context.Context, bool) {
	switch req.Command {
	case statute.CommandConnect:
		return ctx, p.EnableConnect
	case statute.CommandBind:
		return ctx, p.EnableBind
	case statute.CommandAssociate:
		return ctx, p.EnableAssociate
	}
	return ctx, false
}

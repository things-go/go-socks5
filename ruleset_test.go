package socks5

import (
	"context"
	"testing"
)

func TestPermitCommand(t *testing.T) {
	ctx := context.Background()
	r := &PermitCommand{true, false, false}

	if _, ok := r.Allow(ctx, &Request{Header: Header{Command: CommandConnect}}); !ok {
		t.Fatalf("expect connect")
	}

	if _, ok := r.Allow(ctx, &Request{Header: Header{Command: CommandBind}}); ok {
		t.Fatalf("do not expect bind")
	}

	if _, ok := r.Allow(ctx, &Request{Header: Header{Command: CommandAssociate}}); ok {
		t.Fatalf("do not expect associate")
	}
}

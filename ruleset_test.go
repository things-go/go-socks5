package socks5

import (
	"context"
	"testing"

	"github.com/thinkgos/go-socks5/statute"
)

func TestPermitCommand(t *testing.T) {
	ctx := context.Background()
	r := &PermitCommand{true, false, false}

	if _, ok := r.Allow(ctx, &Request{Header: statute.Header{Command: statute.CommandConnect}}); !ok {
		t.Fatalf("expect connect")
	}

	if _, ok := r.Allow(ctx, &Request{Header: statute.Header{Command: statute.CommandBind}}); ok {
		t.Fatalf("do not expect bind")
	}

	if _, ok := r.Allow(ctx, &Request{Header: statute.Header{Command: statute.CommandAssociate}}); ok {
		t.Fatalf("do not expect associate")
	}
}

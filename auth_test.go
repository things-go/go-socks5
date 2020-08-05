package socks5

import (
	"bytes"
	"testing"

	"github.com/thinkgos/go-socks5/statute"
)

func TestNoAuth(t *testing.T) {
	req := bytes.NewBuffer(nil)
	var resp bytes.Buffer

	s := New()
	ctx, err := s.authenticate(&resp, req, "", []byte{statute.MethodNoAuth})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if ctx.Method != statute.MethodNoAuth {
		t.Fatal("Invalid Context Method")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{statute.VersionSocks5, statute.MethodNoAuth}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestPasswordAuth_Valid(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}

	cator := UserPassAuthenticator{Credentials: cred}

	s := New(WithAuthMethods([]Authenticator{cator}))

	ctx, err := s.authenticate(&resp, req, "", []byte{statute.MethodUserPassAuth})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if ctx.Method != statute.MethodUserPassAuth {
		t.Fatal("Invalid Context Method")
	}

	val, ok := ctx.Payload["username"]
	if !ok {
		t.Fatal("Missing key username in auth context's payload")
	}

	if val != "foo" {
		t.Fatal("Invalid username in auth context's payload")
	}

	val, ok = ctx.Payload["password"]
	if !ok {
		t.Fatal("Missing key password in auth context's payload")
	}

	if val != "bar" {
		t.Fatal("Invalid username in auth context's payload")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{statute.VersionSocks5, statute.MethodUserPassAuth, 1, statute.AuthSuccess}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestPasswordAuth_Invalid(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'z'})
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: cred}
	s := New(WithAuthMethods([]Authenticator{cator}))

	ctx, err := s.authenticate(&resp, req, "", []byte{statute.MethodNoAuth, statute.MethodUserPassAuth})
	if err != statute.ErrUserAuthFailed {
		t.Fatalf("err: %v", err)
	}

	if ctx != nil {
		t.Fatal("Invalid Context Method")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{statute.VersionSocks5, statute.MethodUserPassAuth, 1, statute.AuthFailure}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestNoSupportedAuth(t *testing.T) {
	req := bytes.NewBuffer(nil)
	var resp bytes.Buffer

	cred := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: cred}

	s := New(WithAuthMethods([]Authenticator{cator}))

	ctx, err := s.authenticate(&resp, req, "", []byte{statute.MethodNoAuth})
	if err != statute.ErrNoSupportedAuth {
		t.Fatalf("err: %v", err)
	}

	if ctx != nil {
		t.Fatal("Invalid Context Method")
	}

	out := resp.Bytes()
	if !bytes.Equal(out, []byte{statute.VersionSocks5, statute.MethodNoAcceptable}) {
		t.Fatalf("bad: %v", out)
	}
}

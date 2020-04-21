package socks5

import (
	"bytes"
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

func TestSOCKS5_Connect(t *testing.T) {
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
			t.Fatalf("err: %v", err)
		}

		if !bytes.Equal(buf, []byte("ping")) {
			t.Fatalf("bad: %v", buf)
		}
		conn.Write([]byte("pong"))
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	// Create a socks server
	cator := UserPassAuthenticator{
		Credentials: StaticCredentials{"foo": "bar"},
	}
	serv := New(
		WithAuthMethods([]Authenticator{cator}),
		WithLogger(NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)

	// Start listening
	go func() {
		if err := serv.ListenAndServe("tcp", "127.0.0.1:12365"); err != nil {
			t.Fatalf("err: %v", err)
		}
	}()
	time.Sleep(10 * time.Millisecond)

	// Get a local conn
	conn, err := net.Dial("tcp", "127.0.0.1:12365")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Connect, auth and connec to local
	req := new(bytes.Buffer)
	req.Write([]byte{VersionSocks5, 2, MethodNoAuth, MethodUserPassAuth})
	req.Write([]byte{UserPassAuthVersion, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	reqHead := Header{
		Version:  VersionSocks5,
		Command:  CommandConnect,
		Reserved: 0,
		Address: AddrSpec{
			"",
			net.ParseIP("127.0.0.1"),
			lAddr.Port,
		},
		addrType: ATYPIPv4,
	}
	req.Write(reqHead.Bytes())
	// Send a ping
	req.Write([]byte("ping"))

	// Send all the bytes
	conn.Write(req.Bytes())

	// Verify response
	expected := []byte{
		VersionSocks5, MethodUserPassAuth, // use user password auth
		UserPassAuthVersion, AuthSuccess, // response auth success
	}
	rspHead := Header{
		Version:  VersionSocks5,
		Command:  successReply,
		Reserved: 0,
		Address: AddrSpec{
			"",
			net.ParseIP("127.0.0.1"),
			0, // Ignore the port
		},
		addrType: ATYPIPv4,
	}
	expected = append(expected, rspHead.Bytes()...)
	expected = append(expected, []byte("pong")...)

	out := make([]byte, len(expected))
	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(conn, out); err != nil {
		t.Fatalf("err: %v", err)
	}

	t.Logf("proxy bind port: %d", buildPort(out[12], out[13]))

	// Ignore the port
	out[12] = 0
	out[13] = 0

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v", out)
	}
}

func TestSOCKS5_Associate(t *testing.T) {
	locIP := net.ParseIP("127.0.0.1")
	// Create a local listener
	lAddr := &net.UDPAddr{
		IP:   locIP,
		Port: 12398,
	}
	l, err := net.ListenUDP("udp", lAddr)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer l.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, remote, err := l.ReadFrom(buf)
			if err != nil {
				return
			}
			if !bytes.Equal(buf[:n], []byte("ping")) {
				t.Fatalf("bad: %v", buf)
			}
			l.WriteTo([]byte("pong"), remote)
		}
	}()

	// Create a socks server
	cator := UserPassAuthenticator{Credentials: StaticCredentials{"foo": "bar"}}
	serv := New(
		WithAuthMethods([]Authenticator{cator}),
		WithLogger(NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)
	// Start listening
	go func() {
		if err := serv.ListenAndServe("tcp", "127.0.0.1:12355"); err != nil {
			t.Fatalf("err: %v", err)
		}
	}()
	time.Sleep(10 * time.Millisecond)

	// Get a local conn
	conn, err := net.Dial("tcp", "127.0.0.1:12355")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Connect, auth and connec to local
	req := new(bytes.Buffer)
	req.Write([]byte{VersionSocks5, 2, MethodNoAuth, MethodUserPassAuth})
	req.Write([]byte{UserPassAuthVersion, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	reqHead := Header{
		Version:  VersionSocks5,
		Command:  CommandAssociate,
		Reserved: 0,
		Address: AddrSpec{
			"",
			locIP,
			lAddr.Port,
		},
		addrType: ATYPIPv4,
	}
	req.Write(reqHead.Bytes())
	// Send all the bytes
	conn.Write(req.Bytes())

	// Verify response
	expected := []byte{
		VersionSocks5, MethodUserPassAuth, // use user password auth
		UserPassAuthVersion, AuthSuccess, // response auth success
	}

	out := make([]byte, len(expected))
	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(conn, out); err != nil {
		t.Fatalf("err: %v", err)
	}

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v", out)
	}

	rspHead, err := Parse(conn)
	if err != nil {
		t.Fatalf("bad response header: %v", err)
	}
	if rspHead.Version != VersionSocks5 && rspHead.Command != successReply {
		t.Fatalf("parse success but bad header: %v", rspHead)
	}

	t.Logf("proxy bind listen port: %d", rspHead.Address.Port)

	udpConn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   locIP,
		Port: rspHead.Address.Port,
	})
	if err != nil {
		t.Fatalf("bad dial: %v", err)
	}
	// Send a ping
	udpConn.Write(append([]byte{0, 0, 0, ATYPIPv4, 0, 0, 0, 0, 0, 0}, []byte("ping")...))
	response := make([]byte, 1024)
	n, _, err := udpConn.ReadFrom(response)
	if !bytes.Equal(response[n-4:n], []byte("pong")) {
		t.Fatalf("bad udp read: %v", string(response[:n]))
	}
	time.Sleep(time.Second * 1)
}

func Test_SocksWithProxy(t *testing.T) {
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
			t.Fatalf("err: %v", err)
		}

		if !bytes.Equal(buf, []byte("ping")) {
			t.Fatalf("bad: %v", buf)
		}
		conn.Write([]byte("pong"))
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	// Create a socks server
	cator := UserPassAuthenticator{Credentials: StaticCredentials{"foo": "bar"}}
	serv := New(
		WithAuthMethods([]Authenticator{cator}),
		WithLogger(NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)

	// Start listening
	go func() {
		if err := serv.ListenAndServe("tcp", "127.0.0.1:12395"); err != nil {
			t.Fatalf("err: %v", err)
		}
	}()
	time.Sleep(10 * time.Millisecond)

	dial, err := proxy.SOCKS5("tcp", "127.0.0.1:12395", &proxy.Auth{"foo", "bar"}, proxy.Direct)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Connect, auth and connect to local
	conn, err := dial.Dial("tcp", lAddr.String())
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Send a ping
	conn.Write([]byte("ping"))

	out := make([]byte, 4)
	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(conn, out); err != nil {
		t.Fatalf("err: %v", err)
	}

	if !bytes.Equal(out, []byte("pong")) {
		t.Fatalf("bad: %v", out)
	}
}

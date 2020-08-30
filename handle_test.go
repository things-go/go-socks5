package socks5

import (
	"bytes"
	"io"
	"log"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/thinkgos/go-socks5/bufferpool"
	"github.com/thinkgos/go-socks5/statute"
)

type MockConn struct {
	buf bytes.Buffer
}

func (m *MockConn) Write(b []byte) (int, error) {
	return m.buf.Write(b)
}

func (m *MockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: []byte{127, 0, 0, 1}, Port: 65432}
}

func TestRequest_Connect(t *testing.T) {
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		conn, err := l.Accept()
		require.NoError(t, err)
		defer conn.Close()

		buf := make([]byte, 4)
		_, err = io.ReadAtLeast(conn, buf, 4)
		require.NoError(t, err)
		require.Equal(t, []byte("ping"), buf)

		conn.Write([]byte("pong")) // nolint: errcheck
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	// Make proxy server
	proxySrv := &Server{
		rules:      NewPermitAll(),
		resolver:   DNSResolver{},
		logger:     NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags)),
		bufferPool: bufferpool.NewPool(32 * 1024),
	}

	// Create the connect request
	buf := bytes.NewBuffer([]byte{
		statute.VersionSocks5, statute.CommandConnect, 0,
		statute.ATYPIPv4, 127, 0, 0, 1, byte(lAddr.Port >> 8), byte(lAddr.Port),
	})
	// Send a ping
	buf.Write([]byte("ping"))

	// Handle the request
	rsp := new(MockConn)
	req, err := ParseRequest(buf)
	require.NoError(t, err)

	err = proxySrv.handleRequest(rsp, req)
	require.NoError(t, err)

	// Verify response
	out := rsp.buf.Bytes()
	expected := []byte{
		statute.VersionSocks5, statute.RepSuccess, 0,
		statute.ATYPIPv4, 127, 0, 0, 1, 0, 0,
		'p', 'o', 'n', 'g',
	}

	// Ignore the port for both
	out[8] = 0
	out[9] = 0
	require.Equal(t, expected, out)
}

func TestRequest_Connect_RuleFail(t *testing.T) {
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		conn, err := l.Accept()
		require.NoError(t, err)
		defer conn.Close()

		buf := make([]byte, 4)
		_, err = io.ReadAtLeast(conn, buf, 4)
		require.NoError(t, err)
		require.Equal(t, []byte("ping"), buf)

		conn.Write([]byte("pong")) // nolint: errcheck
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	// Make server
	s := &Server{
		rules:      NewPermitNone(),
		resolver:   DNSResolver{},
		logger:     NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags)),
		bufferPool: bufferpool.NewPool(32 * 1024),
	}

	// Create the connect request
	buf := bytes.NewBuffer([]byte{
		statute.VersionSocks5, statute.CommandConnect, 0,
		statute.ATYPIPv4, 127, 0, 0, 1, byte(lAddr.Port >> 8), byte(lAddr.Port),
	})

	// Send a ping
	buf.Write([]byte("ping"))

	// Handle the request
	rsp := new(MockConn)
	req, err := ParseRequest(buf)
	require.NoError(t, err)

	err = s.handleRequest(rsp, req)
	require.Contains(t, err.Error(), "blocked by rules")

	// Verify response
	out := rsp.buf.Bytes()
	expected := []byte{
		statute.VersionSocks5, statute.RepRuleFailure, 0,
		statute.ATYPIPv4, 0, 0, 0, 0, 0, 0,
	}
	require.Equal(t, expected, out)
}

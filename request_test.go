package socks5

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
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

	// Make server
	proxySrv := &Server{
		rules:      NewPermitAll(),
		resolver:   DNSResolver{},
		logger:     NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags)),
		bufferPool: newPool(32 * 1024),
	}

	// Create the connect request
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1}) // nolint: errcheck

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	buf.Write(port) // nolint: errcheck

	// Send a ping
	buf.Write([]byte("ping")) // nolint: errcheck

	// Handle the request
	resp := &MockConn{}
	req, err := NewRequest(buf)
	require.NoError(t, err)

	err = proxySrv.handleRequest(resp, req)
	require.NoError(t, err)

	// Verify response
	out := resp.buf.Bytes()
	expected := []byte{
		5,
		0,
		0,
		1,
		127, 0, 0, 1,
		0, 0,
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
		bufferPool: newPool(32 * 1024),
	}

	// Create the connect request
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	buf.Write(port)

	// Send a ping
	buf.Write([]byte("ping"))

	// Handle the request
	resp := &MockConn{}
	req, err := NewRequest(buf)
	require.NoError(t, err)

	err = s.handleRequest(resp, req)
	require.Contains(t, err.Error(), "blocked by rules")

	// Verify response
	out := resp.buf.Bytes()
	expected := []byte{
		5,
		2,
		0,
		1,
		0, 0, 0, 0,
		0, 0,
	}
	require.Equal(t, expected, out)
}

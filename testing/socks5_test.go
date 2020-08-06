package testing

import (
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"

	"github.com/thinkgos/go-socks5"
	"github.com/thinkgos/go-socks5/bufferpool"
	"github.com/thinkgos/go-socks5/ccsocks5"
)

func Test_Socks5_Connect(t *testing.T) {
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
		assert.Equal(t, []byte("ping"), buf)

		conn.Write([]byte("pong")) // nolint: errcheck
	}()

	// Create a socks server with UserPass auth.
	cator := socks5.UserPassAuthenticator{Credentials: socks5.StaticCredentials{"user": "pass"}}
	srv := socks5.NewServer(
		socks5.WithAuthMethods([]socks5.Authenticator{cator}),
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)

	// Start listening
	go func() {
		err := srv.ListenAndServe("tcp", "127.0.0.1:12389")
		require.NoError(t, err)
	}()
	time.Sleep(10 * time.Millisecond)

	// Get a local conn
	client := ccsocks5.NewClient("127.0.0.1:12389",
		ccsocks5.WithAuth(&proxy.Auth{User: "user", Password: "pass"}),
		ccsocks5.WithBufferPool(bufferpool.NewPool(32*1024)),
	)

	conn, err := client.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	// Send all the bytes
	conn.Write([]byte("ping")) // nolint: errcheck

	out := make([]byte, 4)
	conn.SetDeadline(time.Now().Add(time.Second)) // nolint: errcheck
	_, err = io.ReadFull(conn, out)
	conn.SetDeadline(time.Time{}) // nolint: errcheck
	require.NoError(t, err)
	assert.Equal(t, []byte("pong"), out)
}

func Test_socks5_Associate(t *testing.T) {
	locIP := net.ParseIP("127.0.0.1")
	// Create a local listener
	lAddr := &net.UDPAddr{IP: locIP, Port: 12312}
	l, err := net.ListenUDP("udp", lAddr)
	require.NoError(t, err)
	defer l.Close()

	go func() {
		buf := make([]byte, 2048)
		for {
			n, remote, err := l.ReadFrom(buf)
			if err != nil {
				return
			}
			require.Equal(t, []byte("ping"), buf[:n])

			l.WriteTo([]byte("pong"), remote) // nolint: errcheck
		}
	}()

	// Create a socks server
	cator := socks5.UserPassAuthenticator{Credentials: socks5.StaticCredentials{"user": "pass"}}
	proxySrv := socks5.NewServer(
		socks5.WithAuthMethods([]socks5.Authenticator{cator}),
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)
	// Start listening
	go func() {
		err := proxySrv.ListenAndServe("tcp", "127.0.0.1:9385")
		require.NoError(t, err)
	}()
	time.Sleep(10 * time.Millisecond)

	// Get a local conn
	client := ccsocks5.NewClient(
		"127.0.0.1:9385",
		ccsocks5.WithAuth(&proxy.Auth{User: "user", Password: "pass"}),
	)

	conn, err := client.Dial("udp", lAddr.String())
	require.NoError(t, err)

	// send ping
	conn.Write([]byte("ping")) // nolint: errcheck

	// read response
	out := make([]byte, 4)
	conn.SetDeadline(time.Now().Add(time.Second)) // nolint: errcheck
	_, err = io.ReadFull(conn, out)
	conn.SetDeadline(time.Time{}) // nolint: errcheck
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), out)
	time.Sleep(time.Second * 1)
}

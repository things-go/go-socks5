package socks5

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"

	"github.com/thinkgos/go-socks5/statute"
)

func TestSOCKS5_Connect(t *testing.T) {
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
	lAddr := l.Addr().(*net.TCPAddr)

	// Create a socks server with UserPass auth.
	cator := UserPassAuthenticator{StaticCredentials{"foo": "bar"}}
	srv := NewServer(
		WithAuthMethods([]Authenticator{cator}),
		WithLogger(NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)

	// Start listening
	go func() {
		err := srv.ListenAndServe("tcp", "127.0.0.1:12365")
		require.NoError(t, err)
	}()
	time.Sleep(10 * time.Millisecond)

	// Get a local conn
	conn, err := net.Dial("tcp", "127.0.0.1:12365")
	require.NoError(t, err)

	// Connect, auth and connec to local
	req := bytes.NewBuffer(
		[]byte{
			statute.VersionSocks5, 2, statute.MethodNoAuth, statute.MethodUserPassAuth, // methods
			statute.UserPassAuthVersion, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r', // userpass auth
		})
	reqHead := statute.Request{
		Version:  statute.VersionSocks5,
		Command:  statute.CommandConnect,
		Reserved: 0,
		DstAddr: statute.AddrSpec{
			FQDN:     "",
			IP:       net.ParseIP("127.0.0.1"),
			Port:     lAddr.Port,
			AddrType: statute.ATYPIPv4,
		},
	}
	req.Write(reqHead.Bytes())
	// Send a ping
	req.Write([]byte("ping"))

	// Send all the bytes
	conn.Write(req.Bytes()) // nolint: errcheck

	// Verify response
	expected := []byte{
		statute.VersionSocks5, statute.MethodUserPassAuth, // response use UserPass auth
		statute.UserPassAuthVersion, statute.AuthSuccess, // response auth success
	}
	rspHead := statute.Request{
		Version:  statute.VersionSocks5,
		Command:  statute.RepSuccess,
		Reserved: 0,
		DstAddr: statute.AddrSpec{
			FQDN:     "",
			IP:       net.ParseIP("127.0.0.1"),
			Port:     0,
			AddrType: statute.ATYPIPv4,
		},
	}
	expected = append(expected, rspHead.Bytes()...)
	expected = append(expected, []byte("pong")...)

	out := make([]byte, len(expected))
	conn.SetDeadline(time.Now().Add(time.Second)) // nolint: errcheck
	_, err = io.ReadFull(conn, out)
	conn.SetDeadline(time.Time{}) // nolint: errcheck
	require.NoError(t, err)
	// Ignore the port
	out[12] = 0
	out[13] = 0
	assert.Equal(t, expected, out)
}

func TestSOCKS5_Associate(t *testing.T) {
	locIP := net.ParseIP("127.0.0.1")
	// Create a local listener
	lAddr := &net.UDPAddr{IP: locIP, Port: 12399}
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
	cator := UserPassAuthenticator{StaticCredentials{"foo": "bar"}}
	proxySrv := NewServer(
		WithAuthMethods([]Authenticator{cator}),
		WithLogger(NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)
	// Start listening
	go func() {
		err := proxySrv.ListenAndServe("tcp", "127.0.0.1:12355")
		require.NoError(t, err)
	}()
	time.Sleep(10 * time.Millisecond)

	// Get a local conn
	conn, err := net.Dial("tcp", "127.0.0.1:12355")
	require.NoError(t, err)

	// Connect, auth and connec to local
	req := bytes.NewBuffer(
		[]byte{
			statute.VersionSocks5, 2, statute.MethodNoAuth, statute.MethodUserPassAuth,
			statute.UserPassAuthVersion, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r',
		})
	reqHead := statute.Request{
		Version:  statute.VersionSocks5,
		Command:  statute.CommandAssociate,
		Reserved: 0,
		DstAddr: statute.AddrSpec{
			FQDN:     "",
			IP:       locIP,
			Port:     lAddr.Port,
			AddrType: statute.ATYPIPv4,
		},
	}
	req.Write(reqHead.Bytes())
	// Send all the bytes
	conn.Write(req.Bytes()) // nolint: errcheck

	// Verify response
	expected := []byte{
		statute.VersionSocks5, statute.MethodUserPassAuth, // use user password auth
		statute.UserPassAuthVersion, statute.AuthSuccess, // response auth success
	}

	out := make([]byte, len(expected))
	conn.SetDeadline(time.Now().Add(time.Second)) // nolint: errcheck
	_, err = io.ReadFull(conn, out)
	conn.SetDeadline(time.Time{}) // nolint: errcheck
	require.NoError(t, err)
	require.Equal(t, expected, out)

	rspHead, err := statute.ParseReply(conn)
	require.NoError(t, err)
	require.Equal(t, statute.VersionSocks5, rspHead.Version)
	require.Equal(t, statute.RepSuccess, rspHead.Response)

	// t.Logf("proxy bind listen port: %d", rspHead.BndAddr.Port)
	udpConn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   locIP,
		Port: rspHead.BndAddr.Port,
	})
	require.NoError(t, err)
	// Send a ping
	udpConn.Write(append([]byte{0, 0, 0, statute.ATYPIPv4, 0, 0, 0, 0, 0, 0}, []byte("ping")...)) // nolint: errcheck
	response := make([]byte, 1024)
	n, _, err := udpConn.ReadFrom(response)
	require.NoError(t, err)
	assert.Equal(t, []byte("pong"), response[n-4:n])

	time.Sleep(time.Second * 1)
}

func Test_SocksWithProxy(t *testing.T) {
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

	// Create a socks server with UserPass auth.
	cator := UserPassAuthenticator{StaticCredentials{"foo": "bar"}}
	serv := NewServer(
		WithAuthMethods([]Authenticator{cator}),
		WithLogger(NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)
	// Start socks server
	go func() {
		err := serv.ListenAndServe("tcp", "127.0.0.1:12395")
		require.NoError(t, err)
	}()
	time.Sleep(10 * time.Millisecond)

	// client
	dial, err := proxy.SOCKS5("tcp", "127.0.0.1:12395", &proxy.Auth{User: "foo", Password: "bar"}, proxy.Direct)
	require.NoError(t, err)

	// Connect, auth and connect to local
	conn, err := dial.Dial("tcp", lAddr.String())
	require.NoError(t, err)

	// Send a ping
	conn.Write([]byte("ping")) // nolint: errcheck

	out := make([]byte, 4)
	conn.SetDeadline(time.Now().Add(time.Second)) // nolint: errcheck
	_, err = io.ReadFull(conn, out)
	conn.SetDeadline(time.Time{}) // nolint: errcheck
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), out)
}

/*****************************    auth        *******************************/

func TestNoAuth_Server(t *testing.T) {
	req := bytes.NewBuffer(nil)
	rsp := new(bytes.Buffer)
	s := NewServer(WithAuthMethods([]Authenticator{&NoAuthAuthenticator{}}))

	ctx, err := s.authenticate(rsp, req, "", []byte{statute.MethodNoAuth})
	require.NoError(t, err)
	assert.Equal(t, statute.MethodNoAuth, ctx.Method)
	assert.Equal(t, []byte{statute.VersionSocks5, statute.MethodNoAuth}, rsp.Bytes())
}

func TestPasswordAuth_Valid_Server(t *testing.T) {
	req := bytes.NewBuffer([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	rsp := new(bytes.Buffer)
	cator := UserPassAuthenticator{
		StaticCredentials{"foo": "bar"},
	}
	s := NewServer(WithAuthMethods([]Authenticator{cator}))

	ctx, err := s.authenticate(rsp, req, "", []byte{statute.MethodUserPassAuth})
	require.NoError(t, err)
	assert.Equal(t, statute.MethodUserPassAuth, ctx.Method)

	val, ok := ctx.Payload["username"]
	require.True(t, ok)
	require.Equal(t, "foo", val)

	val, ok = ctx.Payload["password"]
	require.True(t, ok)
	require.Equal(t, "bar", val)

	assert.Equal(t, []byte{statute.VersionSocks5, statute.MethodUserPassAuth, 1, statute.AuthSuccess}, rsp.Bytes())
}

func TestPasswordAuth_Invalid_Server(t *testing.T) {
	req := bytes.NewBuffer([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'z'})
	rsp := new(bytes.Buffer)
	cator := UserPassAuthenticator{
		StaticCredentials{"foo": "bar"},
	}
	s := NewServer(WithAuthMethods([]Authenticator{cator}))

	ctx, err := s.authenticate(rsp, req, "", []byte{statute.MethodNoAuth, statute.MethodUserPassAuth})
	require.True(t, errors.Is(err, statute.ErrUserAuthFailed))
	require.Nil(t, ctx)

	assert.Equal(t, []byte{statute.VersionSocks5, statute.MethodUserPassAuth, 1, statute.AuthFailure}, rsp.Bytes())
}

func TestNoSupportedAuth_Server(t *testing.T) {
	req := bytes.NewBuffer(nil)
	rsp := new(bytes.Buffer)
	cator := UserPassAuthenticator{
		StaticCredentials{"foo": "bar"},
	}

	s := NewServer(WithAuthMethods([]Authenticator{cator}))

	ctx, err := s.authenticate(rsp, req, "", []byte{statute.MethodNoAuth})
	require.True(t, errors.Is(err, statute.ErrNoSupportedAuth))
	require.Nil(t, ctx)

	assert.Equal(t, []byte{statute.VersionSocks5, statute.MethodNoAcceptable}, rsp.Bytes())
}

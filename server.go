package socks5

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"

	"github.com/thinkgos/go-socks5/statute"
)

// GPool is used to implement custom goroutine pool default use goroutine
type GPool interface {
	Submit(f func()) error
}

// Server is reponsible for accepting connections and handling
// the details of the SOCKS5 protocol
type Server struct {
	authMethods map[uint8]Authenticator
	// AuthMethods can be provided to implement custom authentication
	// By default, "auth-less" mode is enabled.
	// For password-based auth use UserPassAuthenticator.
	authCustomMethods []Authenticator
	// If provided, username/password authentication is enabled,
	// by appending a UserPassAuthenticator to AuthMethods. If not provided,
	// and AUthMethods is nil, then "auth-less" mode is enabled.
	credentials CredentialStore
	// resolver can be provided to do custom name resolution.
	// Defaults to DNSResolver if not provided.
	resolver NameResolver
	// rules is provided to enable custom logic around permitting
	// various commands. If not provided, PermitAll is used.
	rules RuleSet
	// rewriter can be used to transparently rewrite addresses.
	// This is invoked before the RuleSet is invoked.
	// Defaults to NoRewrite.
	rewriter AddressRewriter
	// bindIP is used for bind or udp associate
	bindIP net.IP
	// logger can be used to provide a custom log target.
	// Defaults to ioutil.Discard.
	logger Logger
	// Optional function for dialing out
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// buffer pool
	bufferPool *pool
	// goroutine pool
	gPool GPool
	// user's handle
	userConnectHandle   func(ctx context.Context, writer io.Writer, request *Request) error
	userBindHandle      func(ctx context.Context, writer io.Writer, request *Request) error
	userAssociateHandle func(ctx context.Context, writer io.Writer, request *Request) error
}

// New creates a new Server and potentially returns an error
func New(opts ...Option) *Server {
	server := &Server{
		authMethods:       make(map[uint8]Authenticator),
		authCustomMethods: []Authenticator{&NoAuthAuthenticator{}},
		bufferPool:        newPool(2 * 1024),
		resolver:          DNSResolver{},
		rules:             PermitAll(),
		logger:            NewLogger(log.New(ioutil.Discard, "socks5: ", log.LstdFlags)),
		dial: func(ctx context.Context, net_, addr string) (net.Conn, error) {
			return net.Dial(net_, addr)
		},
	}

	for _, opt := range opts {
		opt(server)
	}

	// Ensure we have at least one authentication method enabled
	if len(server.authCustomMethods) == 0 && server.credentials != nil {
		server.authCustomMethods = []Authenticator{&UserPassAuthenticator{server.credentials}}
	}

	for _, v := range server.authCustomMethods {
		server.authMethods[v.GetCode()] = v
	}

	return server
}

// ListenAndServe is used to create a listener and serve on it
func (s *Server) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// Serve is used to serve connections from a listener
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		s.submit(func() {
			err := s.ServeConn(conn)
			if err != nil {
				s.logger.Errorf("server conn %v", err)
			}
		})
	}
}

// ServeConn is used to serve a single connection.
func (s *Server) ServeConn(conn net.Conn) error {
	defer conn.Close()
	bufConn := bufio.NewReader(conn)

	/*
		The SOCKS handshake is formed as follows:
		+-----+----------+---------------+
		| VER | NMETHODS |    METHODS    |
		+-----+----------+---------------+
		|  1  |     1    | X'00' - X'FF' |
		+-----+----------+---------------+
	*/
	// Read the version byte
	version := []byte{0}
	if _, err := bufConn.Read(version); err != nil {
		s.logger.Errorf("failed to get version byte: %v", err)
		return err
	}

	var authContext *AuthContext
	var err error
	// Ensure we are compatible
	if version[0] == statute.VersionSocks5 {
		// Authenticate the connection
		authContext, err = s.authenticate(conn, bufConn, conn.RemoteAddr().String())
		if err != nil {
			err = fmt.Errorf("failed to authenticate: %v", err)
			s.logger.Errorf("%v", err)
			return err
		}
	} else if version[0] != statute.VersionSocks4 {
		err := fmt.Errorf("unsupported SOCKS version: %v", version[0])
		s.logger.Errorf("%v", err)
		return err
	}

	// The client request detail
	request, err := NewRequest(bufConn)
	if err != nil {
		if err == statute.ErrUnrecognizedAddrType {
			if err := SendReply(conn, statute.Header{Version: version[0]}, statute.RepAddrTypeNotSupported); err != nil {
				return fmt.Errorf("failed to send reply, %v", err)
			}
		}
		return fmt.Errorf("failed to read destination address, %v", err)
	}
	if request.Header.Version == statute.VersionSocks5 {
		request.AuthContext = authContext
	}
	request.LocalAddr = conn.LocalAddr()
	request.RemoteAddr = conn.RemoteAddr()
	// Process the client request
	if err := s.handleRequest(conn, request); err != nil {
		err = fmt.Errorf("failed to handle request, %v", err)
		s.logger.Errorf("%v", err)
		return err
	}
	return nil
}

func (s *Server) submit(f func()) {
	if s.gPool == nil || s.gPool.Submit(f) != nil {
		go f()
	}
}

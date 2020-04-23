package socks5

import (
	"fmt"
	"io"
)

// auth defined
const (
	MethodNoAuth        = uint8(0)
	MethodGSSAPI        = uint8(1)
	MethodUserPassAuth  = uint8(2)
	MethodNoAcceptable  = uint8(255)
	UserPassAuthVersion = uint8(1)
	AuthSuccess         = uint8(0)
	AuthFailure         = uint8(1)
)

// auth error defined
var (
	ErrUserAuthFailed  = fmt.Errorf("user authentication failed")
	ErrNoSupportedAuth = fmt.Errorf("no supported authentication mechanism")
)

// AuthContext A Request encapsulates authentication state provided
// during negotiation
type AuthContext struct {
	// Provided auth method
	Method uint8
	// Payload provided during negotiation.
	// Keys depend on the used auth method.
	// For UserPassauth contains username/password
	Payload map[string]string
}

// Authenticator provide auth
type Authenticator interface {
	Authenticate(reader io.Reader, writer io.Writer, userAddr string) (*AuthContext, error)
	GetCode() uint8
}

// NoAuthAuthenticator is used to handle the "No Authentication" mode
type NoAuthAuthenticator struct{}

// GetCode implement interface Authenticator
func (a NoAuthAuthenticator) GetCode() uint8 {
	return MethodNoAuth
}

// Authenticate implement interface Authenticator
func (a NoAuthAuthenticator) Authenticate(_ io.Reader, writer io.Writer, _ string) (*AuthContext, error) {
	_, err := writer.Write([]byte{VersionSocks5, MethodNoAuth})
	return &AuthContext{MethodNoAuth, make(map[string]string)}, err
}

// UserPassAuthenticator is used to handle username/password based
// authentication
type UserPassAuthenticator struct {
	Credentials CredentialStore
}

// GetCode implement interface Authenticator
func (a UserPassAuthenticator) GetCode() uint8 {
	return MethodUserPassAuth
}

// Authenticate implement interface Authenticator
func (a UserPassAuthenticator) Authenticate(reader io.Reader, writer io.Writer, userAddr string) (*AuthContext, error) {
	// Tell the client to use user/pass auth
	if _, err := writer.Write([]byte{VersionSocks5, MethodUserPassAuth}); err != nil {
		return nil, err
	}

	// Get the version and username length
	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(reader, header, 2); err != nil {
		return nil, err
	}

	// Ensure we are compatible
	if header[0] != UserPassAuthVersion {
		return nil, fmt.Errorf("unsupported auth version: %v", header[0])
	}

	// Get the user name
	userLen := int(header[1])
	user := make([]byte, userLen)
	if _, err := io.ReadAtLeast(reader, user, userLen); err != nil {
		return nil, err
	}

	// Get the password length
	if _, err := reader.Read(header[:1]); err != nil {
		return nil, err
	}

	// Get the password
	passLen := int(header[0])
	pass := make([]byte, passLen)
	if _, err := io.ReadAtLeast(reader, pass, passLen); err != nil {
		return nil, err
	}

	// Verify the password
	if a.Credentials.Valid(string(user), string(pass), userAddr) {
		if _, err := writer.Write([]byte{UserPassAuthVersion, AuthSuccess}); err != nil {
			return nil, err
		}
	} else {
		if _, err := writer.Write([]byte{UserPassAuthVersion, AuthFailure}); err != nil {
			return nil, err
		}
		return nil, ErrUserAuthFailed
	}

	// Done
	return &AuthContext{MethodUserPassAuth, map[string]string{"username": string(user), "password": string(pass)}}, nil
}

// authenticate is used to handle connection authentication
func (s *Server) authenticate(conn io.Writer, bufConn io.Reader, userAddr string) (*AuthContext, error) {
	// Get the methods
	methods, err := readMethods(bufConn)
	if err != nil {
		return nil, fmt.Errorf("Failed to get auth methods: %v", err)
	}

	// Select a usable method
	for _, method := range methods {
		cator, found := s.authMethods[method]
		if found {
			return cator.Authenticate(bufConn, conn, userAddr)
		}
	}

	// No usable method found
	return nil, noAcceptableAuth(conn)
}

// noAcceptableAuth is used to handle when we have no eligible
// authentication mechanism
func noAcceptableAuth(conn io.Writer) error {
	conn.Write([]byte{VersionSocks5, MethodNoAcceptable})
	return ErrNoSupportedAuth
}

// readMethods is used to read the number of methods
// and proceeding auth methods
func readMethods(r io.Reader) ([]byte, error) {
	header := []byte{0}
	if _, err := r.Read(header); err != nil {
		return nil, err
	}

	numMethods := int(header[0])
	methods := make([]byte, numMethods)
	_, err := io.ReadAtLeast(r, methods, numMethods)
	return methods, err
}

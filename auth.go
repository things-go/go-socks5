package socks5

import (
	"fmt"
	"io"

	"github.com/thinkgos/go-socks5/statute"
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
	return statute.MethodNoAuth
}

// Authenticate implement interface Authenticator
func (a NoAuthAuthenticator) Authenticate(_ io.Reader, writer io.Writer, _ string) (*AuthContext, error) {
	_, err := writer.Write([]byte{statute.VersionSocks5, statute.MethodNoAuth})
	return &AuthContext{statute.MethodNoAuth, make(map[string]string)}, err
}

// UserPassAuthenticator is used to handle username/password based
// authentication
type UserPassAuthenticator struct {
	Credentials CredentialStore
}

// GetCode implement interface Authenticator
func (a UserPassAuthenticator) GetCode() uint8 {
	return statute.MethodUserPassAuth
}

// Authenticate implement interface Authenticator
func (a UserPassAuthenticator) Authenticate(reader io.Reader, writer io.Writer, userAddr string) (*AuthContext, error) {
	// Tell the client to use user/pass auth
	if _, err := writer.Write([]byte{statute.VersionSocks5, statute.MethodUserPassAuth}); err != nil {
		return nil, err
	}

	nup, err := statute.ParseUserPassRequest(reader)
	if err != nil {
		return nil, err
	}

	// Verify the password
	if !a.Credentials.Valid(string(nup.User), string(nup.Pass), userAddr) {
		if _, err := writer.Write([]byte{statute.UserPassAuthVersion, statute.AuthFailure}); err != nil {
			return nil, err
		}
		return nil, statute.ErrUserAuthFailed
	}

	if _, err := writer.Write([]byte{statute.UserPassAuthVersion, statute.AuthSuccess}); err != nil {
		return nil, err
	}

	// Done
	return &AuthContext{
		statute.MethodUserPassAuth,
		map[string]string{
			"username": string(nup.User),
			"password": string(nup.Pass),
		},
	}, nil
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
	conn.Write([]byte{statute.VersionSocks5, statute.MethodNoAcceptable})
	return statute.ErrNoSupportedAuth
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

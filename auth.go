package socks5

import (
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
	// reply the client to use user/pass auth
	if _, err := writer.Write([]byte{statute.VersionSocks5, statute.MethodUserPassAuth}); err != nil {
		return nil, err
	}
	// get user and user's password
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
func (s *Server) authenticate(conn io.Writer, bufConn io.Reader, userAddr string, methods []byte) (*AuthContext, error) {
	// Select a usable method
	for _, method := range methods {
		if cator, found := s.authMethods[method]; found {
			return cator.Authenticate(bufConn, conn, userAddr)
		}
	}
	// No usable method found
	conn.Write([]byte{statute.VersionSocks5, statute.MethodNoAcceptable}) // nolint: errcheck
	return nil, statute.ErrNoSupportedAuth
}

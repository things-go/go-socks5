package socks5

// CredentialStore is used to support user/pass authentication optional user ip
// if you want to limit user ip ,you can refuse it.
type CredentialStore interface {
	Valid(user, password, userIP string) bool
}

// StaticCredentials enables using a map directly as a credential store
type StaticCredentials map[string]string

func (s StaticCredentials) Valid(user, password, userIP string) bool {
	pass, ok := s[user]
	if !ok {
		return false
	}
	return password == pass
}

package statute

import (
	"fmt"
)

// auth defined
const (
	MethodNoAuth       = byte(0x00)
	MethodGSSAPI       = byte(0x01)
	MethodUserPassAuth = byte(0x02)
	MethodNoAcceptable = byte(0xff)
	// user password version
	UserPassAuthVersion = byte(0x01)
	// auth status
	AuthSuccess = byte(0x00)
	AuthFailure = byte(0x01)
)

// socks const defined
const (
	// protocol version
	VersionSocks5 = byte(0x05)
	// request command
	CommandConnect   = byte(0x01)
	CommandBind      = byte(0x02)
	CommandAssociate = byte(0x03)
	// address type
	ATYPIPv4   = byte(0x01)
	ATYPDomain = byte(0x03)
	ATYPIPv6   = byte(0x04)
)

// reply status
const (
	RepSuccess uint8 = iota
	RepServerFailure
	RepRuleFailure
	RepNetworkUnreachable
	RepHostUnreachable
	RepConnectionRefused
	RepTTLExpired
	RepCommandNotSupported
	RepAddrTypeNotSupported
	// 0x09 - 0xff unassigned
)

// auth error defined
var (
	ErrUserAuthFailed  = fmt.Errorf("user authentication failed")
	ErrNoSupportedAuth = fmt.Errorf("no supported authentication mechanism")
)

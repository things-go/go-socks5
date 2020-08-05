package statute

import (
	"fmt"
	"io"
)

// UserPassRequest is the negotiation user's password request packet
// The SOCKS handshake user's password request is formed as follows:
// 	+--------------+------+----------+------+----------+
// 	| USERPASS_VER | ULEN |   USER   | PLEN |   PASS   |
// 	+--------------+------+----------+------+----------+
// 	|      1      |   1  | Variable |   1  | Variable |
// 	+--------------+------+----------+------+----------+
type UserPassRequest struct {
	Ver  byte
	Ulen byte
	User []byte // 1-255 bytes
	Plen byte
	Pass []byte // 1-255 bytes
}

// NewUserPassRequest new user's password request packet with ver,user, pass
func NewUserPassRequest(ver byte, user, pass []byte) UserPassRequest {
	return UserPassRequest{
		ver,
		byte(len(user)),
		user,
		byte(len(pass)),
		pass,
	}
}

// ParseUserPassRequest parse user's password request.
func ParseUserPassRequest(r io.Reader) (nup UserPassRequest, err error) {
	// Get the version and username length
	header := []byte{0, 0}
	if _, err = io.ReadAtLeast(r, header, 2); err != nil {
		return
	}

	// Ensure we are compatible
	nup.Ver = header[0]
	if nup.Ver != UserPassAuthVersion {
		err = fmt.Errorf("unsupported auth version: %v", header[0])
		return
	}

	// Get the user name
	nup.Ulen = header[1]
	nup.User = make([]byte, nup.Ulen)
	if _, err = io.ReadAtLeast(r, nup.User, int(nup.Ulen)); err != nil {
		return
	}

	// Get the password length
	if _, err = r.Read(header[:1]); err != nil {
		return
	}
	// Get the password
	nup.Plen = header[0]
	nup.Pass = make([]byte, nup.Plen)
	_, err = io.ReadAtLeast(r, nup.Pass, int(nup.Plen))
	return
}

func (sf UserPassRequest) Bytes() []byte {
	b := make([]byte, 0, 3+sf.Ulen+sf.Plen)
	b = append(b, sf.Ver, sf.Ulen)
	b = append(b, sf.User...)
	b = append(b, sf.Plen)
	b = append(b, sf.Pass...)
	return b
}

// UserPassReply is the negotiation user's password reply packet
// The SOCKS handshake user's password response is formed as follows:
// 	+-----+--------+
// 	| VER | status |
// 	+-----+--------+
// 	|  1  |     1  |
// 	+-----+--------+
type UserPassReply struct {
	Ver    byte
	Status byte
}

// ParseUserPassReply parse user's password reply packet.
func ParseUserPassReply(r io.Reader) (n UserPassReply, err error) {
	bb := make([]byte, 2)
	if _, err = io.ReadFull(r, bb); err != nil {
		return
	}
	n.Ver = bb[0]
	n.Status = bb[1]
	return
}

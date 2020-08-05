package statute

import (
	"io"
)

// MethodRequest is the negotiation method request packet
// The SOCKS handshake method request is formed as follows:
// 	+-----+----------+---------------+
// 	| VER | NMETHODS |    METHODS    |
// 	+-----+----------+---------------+
// 	|  1  |     1    | X'00' - X'FF' |
// 	+-----+----------+---------------+
type MethodRequest struct {
	Ver      byte
	NMethods byte
	Methods  []byte // 1-255 bytes
}

// NewMethodRequest new  negotiation method request
func NewMethodRequest(ver byte, medthods []byte) MethodRequest {
	return MethodRequest{
		ver,
		byte(len(medthods)),
		medthods,
	}
}

func (n MethodRequest) Bytes() []byte {
	b := make([]byte, 0, 2+n.NMethods)
	return append(append(b, n.Ver, n.NMethods), n.Methods...)
}

// MethodReply is the negotiation method reply packet
// The SOCKS handshake method response is formed as follows:
// 	+-----+--------+
// 	| VER | METHOD |
// 	+-----+--------+
// 	|  1  |     1  |
// 	+-----+--------+
type MethodReply struct {
	Ver    byte
	Method byte
}

func ParseMethodReply(r io.Reader) (n MethodReply, err error) {
	bb := make([]byte, 2)
	if _, err = io.ReadFull(r, bb); err != nil {
		return
	}
	n.Ver = bb[0]
	n.Method = bb[1]
	return
}

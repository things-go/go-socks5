package ccsocks5

import (
	"net"

	"github.com/thinkgos/go-socks5/bufferpool"
	"github.com/thinkgos/go-socks5/statute"
)

// underConnect under connect
type underConnect struct {
	*net.TCPConn
	remoteAddress net.Addr // real remote address, not the proxy address
}

// RemoteAddr returns the remote network address.
// The Addr returned is shared by all invocations of RemoteAddr,
// so do not modify it.
func (sf *underConnect) RemoteAddr() net.Addr {
	return sf.remoteAddress
}

// underAssociate under associate
type underAssociate struct {
	*net.UDPConn
	bufferPool    bufferpool.BufPool
	remoteAddress net.Addr // real remote address, not the proxy address
}

// Read implements the Conn Read method.
func (sf *underAssociate) Read(b []byte) (int, error) {
	b1 := sf.bufferPool.Get()
	defer sf.bufferPool.Put(b1)

	n, err := sf.UDPConn.Read(b1[:cap(b1)])
	if err != nil {
		return 0, err
	}
	datagram, err := statute.ParseDatagram(b1[:n])
	if err != nil {
		return 0, err
	}
	n = copy(b, datagram.Data)
	return n, nil
}

// Write implements the Conn Write method.
func (sf *underAssociate) Write(b []byte) (int, error) {
	datagram, err := statute.NewDatagram(sf.remoteAddress.String(), b)
	if err != nil {
		return 0, err
	}
	return sf.UDPConn.Write(datagram.Bytes())
}

// RemoteAddr returns the remote network address.
// The Addr returned is shared by all invocations of RemoteAddr,
// so do not modify it.
func (sf *underAssociate) RemoteAddr() net.Addr {
	return sf.remoteAddress
}

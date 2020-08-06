package ccsocks5

import (
	"net"
	"os"
)

// Associate implement sock5 associate command
type Associate struct {
	*Client
}

// SetReadBuffer sets the size of the operating system's receive buffer associated with the connection.
func (sf *Associate) SetReadBuffer(bytes int) error {
	return sf.getUnderAssociate().SetReadBuffer(bytes)
}

// SetWriteBuffer sets the size of the operating system's transmit buffer associated with the connection.
func (sf *Associate) SetWriteBuffer(bytes int) error {
	return sf.getUnderAssociate().SetWriteBuffer(bytes)
}

// ReadFrom implements the PacketConn ReadFrom method.
func (sf *Associate) ReadFrom(b []byte) (int, net.Addr, error) {
	return sf.getUnderAssociate().ReadFrom(b)
}

// ReadFromUDP acts like ReadFrom but returns a UDPAddr.
func (sf *Associate) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	return sf.getUnderAssociate().ReadFromUDP(b)
}

// ReadMsgUDP reads a message from c, copying the payload into b and
// the associated out-of-band data into oob.
func (sf *Associate) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	return sf.getUnderAssociate().ReadMsgUDP(b, oob)
}

// WriteTo implements the PacketConn WriteTo method.
func (sf *Associate) WriteTo(b []byte, addr net.Addr) (int, error) {
	return sf.getUnderAssociate().WriteTo(b, addr)
}

// WriteToUDP acts like WriteTo but takes a UDPAddr.
func (sf *Associate) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	return sf.getUnderAssociate().WriteToUDP(b, addr)
}

// WriteMsgUDP writes a message to addr via c if c isn't connected, or
// to c's remote address if c is connected (in which case addr must be
// nil)
func (sf *Associate) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	return sf.getUnderAssociate().WriteMsgUDP(b, oob, addr)
}

// File returns a copy of the underlying os.File.
func (sf *Associate) File() (f *os.File, err error) {
	return sf.getUnderAssociate().File()
}

func (sf *Associate) getUnderAssociate() *net.UDPConn {
	return sf.Conn.(*underAssociate).UDPConn
}

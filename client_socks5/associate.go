package client_socks5

import (
	"net"
	"os"
)

type Associate struct {
	*Client
}

func (sf *Associate) getUDPConn() *net.UDPConn {
	return sf.underConn.(*underAssociate).udpConn
}

func (sf *Associate) SetReadBuffer(bytes int) error {
	return sf.getUDPConn().SetReadBuffer(bytes)
}

func (sf *Associate) SetWriteBuffer(bytes int) error {
	return sf.getUDPConn().SetWriteBuffer(bytes)
}
func (sf *Associate) ReadFrom(b []byte) (int, net.Addr, error) {
	return sf.getUDPConn().ReadFrom(b)
}
func (sf *Associate) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	return sf.getUDPConn().ReadFromUDP(b)
}
func (sf *Associate) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	return sf.getUDPConn().ReadMsgUDP(b, oob)
}
func (sf *Associate) WriteTo(b []byte, addr net.Addr) (int, error) {
	return sf.getUDPConn().WriteTo(b, addr)
}
func (sf *Associate) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	return sf.getUDPConn().WriteToUDP(b, addr)
}
func (sf *Associate) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	return sf.getUDPConn().WriteMsgUDP(b, oob, addr)
}
func (sf *Associate) File() (f *os.File, err error) {
	return sf.getUDPConn().File()
}

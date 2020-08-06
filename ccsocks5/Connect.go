package ccsocks5

import (
	"io"
	"net"
	"os"
	"time"
)

// Connect implement sock5 connect command
type Connect struct {
	*Client
}

// SetReadBuffer sets the size of the operating system's receive buffer associated with the connection.
func (sf *Connect) SetReadBuffer(bytes int) error {
	return sf.getUnderConnect().SetReadBuffer(bytes)
}

// SetWriteBuffer sets the size of the operating system's transmit buffer associated with the connection.
func (sf *Connect) SetWriteBuffer(bytes int) error {
	return sf.getUnderConnect().SetWriteBuffer(bytes)
}

// SetKeepAlive sets whether the operating system should send
// keep-alive messages on the connection.
func (sf *Connect) SetKeepAlive(keepalive bool) error {
	return sf.getUnderConnect().SetKeepAlive(keepalive)
}

// SetKeepAlivePeriod sets period between keep-alives.
func (sf *Connect) SetKeepAlivePeriod(d time.Duration) error {
	return sf.getUnderConnect().SetKeepAlivePeriod(d)
}

// SetLinger sets the behavior of Close on a connection which still
// has data waiting to be sent or to be acknowledged.
func (sf *Connect) SetLinger(sec int) error {
	return sf.getUnderConnect().SetLinger(sec)
}

// SetNoDelay controls whether the operating system should delay
// packet transmission in hopes of sending fewer packets (Nagle's
// algorithm).  The default is true (no delay), meaning that data is
// sent as soon as possible after a Write.
func (sf *Connect) SetNoDelay(noDelay bool) error {
	return sf.getUnderConnect().SetNoDelay(noDelay)
}

// ReadFrom implements the io.ReaderFrom ReadFrom method.
func (sf *Connect) ReadFrom(r io.Reader) (int64, error) {
	return sf.getUnderConnect().ReadFrom(r)
}

// CloseRead shuts down the reading side of the TCP connection.
// Most callers should just use Close.
func (sf *Connect) CloseRead() error {
	return sf.getUnderConnect().CloseRead()
}

// CloseWrite shuts down the writing side of the TCP connection.
// Most callers should just use Close.
func (sf *Connect) CloseWrite() error {
	return sf.getUnderConnect().CloseWrite()
}

// File returns a copy of the underlying os.File.
func (sf *Connect) File() (f *os.File, err error) {
	return sf.getUnderConnect().File()
}

func (sf *Connect) getUnderConnect() *net.TCPConn {
	return sf.Conn.(*underConnect).TCPConn
}

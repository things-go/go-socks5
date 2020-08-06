package client_socks5

import (
	"io"
	"os"
	"time"
)

type Connect struct {
	*Client
}

func (sf *Connect) SetReadBuffer(bytes int) error {
	return sf.tcpConn.SetReadBuffer(bytes)
}

func (sf *Connect) SetWriteBuffer(bytes int) error {
	return sf.tcpConn.SetWriteBuffer(bytes)
}

func (sf *Connect) SetKeepAlive(keepalive bool) error {
	return sf.tcpConn.SetKeepAlive(keepalive)
}

func (sf *Connect) SetKeepAlivePeriod(d time.Duration) error {
	return sf.tcpConn.SetKeepAlivePeriod(d)
}

func (sf *Connect) SetLinger(sec int) error {
	return sf.tcpConn.SetLinger(sec)
}

func (sf *Connect) SetNoDelay(noDelay bool) error {
	return sf.tcpConn.SetNoDelay(noDelay)
}

func (sf *Connect) ReadFrom(r io.Reader) (int64, error) {
	return sf.tcpConn.ReadFrom(r)
}

func (sf *Connect) CloseRead() error {
	return sf.tcpConn.CloseRead()
}

func (sf *Connect) CloseWrite() error {
	return sf.tcpConn.CloseWrite()
}

func (sf *Connect) File() (f *os.File, err error) {
	return sf.tcpConn.File()
}

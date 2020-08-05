package client

import (
	"errors"
	"net"
	"time"

	"golang.org/x/net/proxy"

	"github.com/thinkgos/go-socks5/statute"
)

// Client is socks5 client wrapper
type Client struct {
	Server string
	Auth   *proxy.Auth
	// On command UDP, let server control the tcp and udp connection relationship
	TCPConn       *net.TCPConn
	UDPConn       *net.UDPConn
	RemoteAddress net.Addr
	TCPDeadline   time.Duration
	TCPTimeout    time.Duration
	UDPDeadline   time.Duration
}

// This is just create a client, you need to use Dial to create conn
func NewClient(addr string, opts ...Option) (*Client, error) {
	c := &Client{
		Server:      addr,
		TCPTimeout:  time.Second,
		TCPDeadline: time.Second,
		UDPDeadline: time.Second,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

func (c *Client) Close() error {
	if c.UDPConn == nil {
		return c.TCPConn.Close()
	}
	if c.TCPConn != nil {
		c.TCPConn.Close()
	}
	return c.UDPConn.Close()
}

func (c *Client) LocalAddr() net.Addr {
	if c.UDPConn == nil {
		return c.TCPConn.LocalAddr()
	}
	return c.UDPConn.LocalAddr()
}

func (c *Client) RemoteAddr() net.Addr {
	return c.RemoteAddress
}

func (c *Client) SetDeadline(t time.Time) error {
	if c.UDPConn == nil {
		return c.TCPConn.SetDeadline(t)
	}
	return c.UDPConn.SetDeadline(t)
}

func (c *Client) SetReadDeadline(t time.Time) error {
	if c.UDPConn == nil {
		return c.TCPConn.SetReadDeadline(t)
	}
	return c.UDPConn.SetReadDeadline(t)
}

func (c *Client) SetWriteDeadline(t time.Time) error {
	if c.UDPConn == nil {
		return c.TCPConn.SetWriteDeadline(t)
	}
	return c.UDPConn.SetWriteDeadline(t)
}

func (c *Client) Read(b []byte) (int, error) {
	if c.UDPConn == nil {
		return c.TCPConn.Read(b)
	}
	b1 := make([]byte, 65535)
	n, err := c.UDPConn.Read(b1)
	if err != nil {
		return 0, err
	}
	pkt := statute.Packet{}
	err = pkt.Parse(b1[:n])
	if err != nil {
		return 0, err
	}
	n = copy(b, pkt.Data)
	return n, nil
}

func (c *Client) Write(b []byte) (int, error) {
	if c.UDPConn == nil {
		return c.TCPConn.Write(b)
	}
	pkt, err := statute.NewPacket(c.RemoteAddress.String(), b)
	if err != nil {
		return 0, err
	}
	return c.UDPConn.Write(pkt.Bytes())
}

func (c *Client) Dial(network, addr string) (net.Conn, error) {
	var err error

	conn := *c // clone a client
	if network == "tcp" {
		conn.RemoteAddress, err = net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			return nil, err
		}

		conn.TCPConn, err = conn.dialServer()
		if err != nil {
			return nil, err
		}
		if err := conn.handshake(); err != nil {
			return nil, err
		}
		a, err := statute.ParseAddrSpec(addr)
		if err != nil {
			return nil, err
		}
		head := statute.Request{
			Version:    statute.VersionSocks5,
			Command:    statute.CommandConnect,
			DstAddress: a,
		}
		if _, err := conn.Write(head.Bytes()); err != nil {
			return nil, err
		}

		rspHead, err := statute.ParseRequest(conn.TCPConn)
		if err != nil {
			return nil, err
		}
		if rspHead.Command != statute.RepSuccess {
			return nil, errors.New("host unreachable")
		}
		return &conn, nil
	}

	if network == "udp" {
		conn.RemoteAddress, err = net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}
		conn.TCPConn, err = conn.dialServer()
		if err != nil {
			return nil, err
		}
		if err := conn.handshake(); err != nil {
			return nil, err
		}
		laddr := &net.UDPAddr{
			IP:   conn.TCPConn.LocalAddr().(*net.TCPAddr).IP,
			Port: conn.TCPConn.LocalAddr().(*net.TCPAddr).Port,
			Zone: conn.TCPConn.LocalAddr().(*net.TCPAddr).Zone,
		}
		a, err := statute.ParseAddrSpec(laddr.String())
		if err != nil {
			return nil, err
		}
		head := statute.Request{
			Version:    statute.VersionSocks5,
			Command:    statute.CommandConnect,
			DstAddress: a,
		}
		if _, err := conn.Write(head.Bytes()); err != nil {
			return nil, err
		}
		rspHead, err := statute.ParseRequest(conn.TCPConn)
		if err != nil {
			return nil, err
		}
		if rspHead.Command != statute.RepSuccess {
			return nil, errors.New("host unreachable")
		}

		raddr, err := net.ResolveUDPAddr("udp", rspHead.DstAddress.String())
		if err != nil {
			return nil, err
		}
		conn.UDPConn, err = net.DialUDP("udp", laddr, raddr)
		if err != nil {
			return nil, err
		}
		return &conn, nil
	}

	return nil, errors.New("not support network")
}

func (c *Client) handshake() error {
	methods := statute.MethodNoAuth
	if c.Auth != nil {
		methods = statute.MethodUserPassAuth
	}

	_, err := c.TCPConn.Write(statute.NewMethodRequest(statute.VersionSocks5, []byte{methods}).Bytes())
	if err != nil {
		return err
	}
	reply, err := statute.ParseMethodReply(c.TCPConn)
	if err != nil {
		return err
	}

	if reply.Ver != statute.VersionSocks5 {
		return statute.ErrNotSupportVersion
	}
	if reply.Method != methods {
		return statute.ErrNotSupportMethod
	}

	if methods == statute.MethodUserPassAuth {
		_, err = c.TCPConn.Write(statute.NewUserPassRequest(statute.UserPassAuthVersion, []byte(c.Auth.User), []byte(c.Auth.Password)).Bytes())
		if err != nil {
			return err
		}

		rsp, err := statute.ParseUserPassReply(c.TCPConn)
		if err != nil {
			return err
		}
		if rsp.Ver != statute.UserPassAuthVersion {
			return statute.ErrNotSupportMethod
		}
		if rsp.Status != statute.RepSuccess {
			return statute.ErrUserAuthFailed
		}
	}
	return nil
}

func (c *Client) dialServer() (*net.TCPConn, error) {
	conn, err := net.Dial("tcp", c.Server)
	if err != nil {
		return nil, err
	}

	TCPConn := conn.(*net.TCPConn)
	if c.TCPTimeout != 0 {
		if err := TCPConn.SetKeepAlivePeriod(c.TCPTimeout); err != nil {
			return nil, err
		}
	}
	if c.TCPDeadline != 0 {
		if err := TCPConn.SetDeadline(time.Now().Add(c.TCPTimeout)); err != nil {
			return nil, err
		}
	}
	return TCPConn, nil
}

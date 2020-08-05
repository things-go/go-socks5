package socks5

import (
	"errors"
	"net"
	"time"

	"github.com/thinkgos/go-socks5/statute"
)

// Client is socks5 client wrapper
type Client struct {
	Server   string
	Version  byte
	UserName string
	Password string
	// On command UDP, let server control the tcp and udp connection relationship
	TCPConn       *net.TCPConn
	UDPConn       *net.UDPConn
	RemoteAddress net.Addr
	TCPDeadline   int
	TCPTimeout    int
	UDPDeadline   int
}

// This is just create a client, you need to use Dial to create conn
func NewClient(addr, username, password string, tcpTimeout, tcpDeadline, udpDeadline int) (*Client, error) {
	c := &Client{
		Server:      addr,
		Version:     statute.VersionSocks5,
		UserName:    username,
		Password:    password,
		TCPTimeout:  tcpTimeout,
		TCPDeadline: tcpDeadline,
		UDPDeadline: udpDeadline,
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
	// TODO: UDP data
	// b1 := make([]byte, 65535)
	// n, err := c.UDPConn.Read(b1)
	// if err != nil {
	// 	return 0, err
	// }
	// d, err := NewDatagramFromBytes(b1[0:n])
	// if err != nil {
	// 	return 0, err
	// }
	// if len(b) < len(d.Data) {
	// 	return 0, errors.New("b too small")
	// }
	// n = copy(b, d.Data)
	return 0, nil
}

func (c *Client) Write(b []byte) (int, error) {
	if c.UDPConn == nil {
		return c.TCPConn.Write(b)
	}
	// TODO: UPD data
	// addr, err := ParseAddrSpec(c.RemoteAddress.String())
	// if err != nil {
	// 	return 0, err
	// }
	// if a == ATYPDomain {
	// 	h = h[1:]
	// }
	// d := NewDatagram(a, h, p, b)
	// b1 := d.Bytes()
	return c.UDPConn.Write(b)
}

func (c *Client) Dial(network, addr string) (net.Conn, error) {
	// var err error
	//
	// conn := *c
	// if network == "tcp" {
	// 	conn.RemoteAddress, err = net.ResolveTCPAddr("tcp", addr)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	if err := conn.Negotiate(); err != nil {
	// 		return nil, err
	// 	}
	// 	a, h, p, err := ParseAddress(addr)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	if a == ATYPDomain {
	// 		h = h[1:]
	// 	}
	// 	if _, err := conn.Request(NewRequest(CommandConnect, a, h, p)); err != nil {
	// 		return nil, err
	// 	}
	// 	return conn, nil
	// }
	//
	// if network == "udp" {
	// 	conn.RemoteAddress, err = net.ResolveUDPAddr("udp", addr)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	if err := conn.Negotiate(); err != nil {
	// 		return nil, err
	// 	}
	//
	// 	laddr := &net.UDPAddr{
	// 		IP:   conn.TCPConn.LocalAddr().(*net.TCPAddr).IP,
	// 		Port: conn.TCPConn.LocalAddr().(*net.TCPAddr).Port,
	// 		Zone: conn.TCPConn.LocalAddr().(*net.TCPAddr).Zone,
	// 	}
	// 	a, h, p, err := ParseAddress(laddr.String())
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	rp, err := conn.Request(NewRequest(CmdUDP, a, h, p))
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	raddr, err := net.ResolveUDPAddr("udp", rp.Address())
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	conn.UDPConn, err = net.DialUDP("udp", laddr, raddr)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	return conn, nil
	// }
	// return nil, errors.New("unsupport network")
	return nil, errors.New("aaa")
}

func (c *Client) handshake() error {
	methods := statute.MethodNoAuth
	if c.UserName != "" && c.Password != "" {
		methods = statute.MethodUserPassAuth
	}

	_, err := c.TCPConn.Write(statute.NewMethodRequest(c.Version, []byte{methods}).Bytes())
	if err != nil {
		return err
	}
	reply, err := statute.ParseMethodReply(c.TCPConn)
	if err != nil {
		return err
	}

	if reply.Ver != c.Version {
		return errors.New("handshake failed cause version not same")
	}
	if reply.Method != methods {
		return errors.New("unsupport method")
	}

	if methods == statute.MethodUserPassAuth {
		_, err = c.TCPConn.Write(statute.NewNegotiationUserPassRequest(statute.UserPassAuthVersion, []byte(c.UserName), []byte(c.Password)).Bytes())
		if err != nil {
			return err
		}

		rsp, err := statute.ParseUserPassReply(c.TCPConn)
		if err != nil {
			return err
		}
		if rsp.Ver != statute.UserPassAuthVersion {
			return errors.New("handshake failed cause version not same")
		}
		if rsp.Status != statute.RepSuccess {
			return statute.ErrUserAuthFailed
		}
	}
	return nil
}

package client_socks5

import (
	"errors"
	"net"
	"time"

	"golang.org/x/net/proxy"

	"github.com/thinkgos/go-socks5/bufferpool"
	"github.com/thinkgos/go-socks5/statute"
)

// Client is socks5 client wrapper
type Client struct {
	proxyAddr string
	auth      *proxy.Auth
	// On command UDP, let server control the tcp and udp connection relationship
	tcpConn         *net.TCPConn
	underConn       net.Conn
	TCPDeadline     time.Duration
	KeepAlivePeriod time.Duration
	UDPDeadline     time.Duration
	bufferPool      bufferpool.BufPool
}

// This is just create a client, you need to use Dial to create conn
func NewClient(proxyAddr string, opts ...Option) (*Client, error) {
	c := &Client{
		proxyAddr:       proxyAddr,
		KeepAlivePeriod: time.Second,
		TCPDeadline:     time.Second,
		UDPDeadline:     time.Second,
		bufferPool:      bufferpool.NewPool(32 * 1024),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

func (sf *Client) Read(b []byte) (int, error) {
	return sf.underConn.Read(b)
}

func (sf *Client) Write(b []byte) (int, error) {
	return sf.underConn.Write(b)
}

func (sf *Client) Close() (err error) {
	err = sf.tcpConn.Close()
	if sf.underConn != nil {
		err = sf.underConn.Close()
	}
	return
}

func (sf *Client) LocalAddr() net.Addr {
	return sf.underConn.LocalAddr()
}

func (sf *Client) RemoteAddr() net.Addr {
	return sf.underConn.RemoteAddr()
}

func (sf *Client) SetDeadline(t time.Time) error {
	return sf.underConn.SetDeadline(t)
}

func (sf *Client) SetReadDeadline(t time.Time) error {
	return sf.underConn.SetReadDeadline(t)
}

func (sf *Client) SetWriteDeadline(t time.Time) error {
	return sf.underConn.SetWriteDeadline(t)
}

func (sf *Client) Dial(network, addr string) (net.Conn, error) {
	if network == "tcp" {
		return sf.DialTCP(network, addr)
	}
	if network == "udp" {
		return sf.DialUDP(network, nil, addr)
	}
	return nil, errors.New("not support network")
}

func (sf *Client) DialTCP(network, addr string) (net.Conn, error) {
	conn := *sf // clone a client

	_, err := net.ResolveTCPAddr(network, addr)
	if err != nil {
		return nil, err
	}
	err = conn.dialProxyServer(network)
	if err != nil {
		return nil, err
	}

	if _, err := conn.handshake(statute.CommandConnect, addr); err != nil {
		conn.Close()
		return nil, err
	}
	conn.underConn = conn.tcpConn
	return &Connect{&conn}, nil
}

func (sf *Client) DialUDP(network string, laddr *net.UDPAddr, raddr string) (net.Conn, error) {
	conn := *sf // clone a client

	remoteAddress, err := net.ResolveUDPAddr(network, raddr)
	if err != nil {
		return nil, err
	}
	err = conn.dialProxyServer("tcp")
	if err != nil {
		return nil, err
	}
	bndAddress, err := conn.handshake(statute.CommandAssociate, raddr)
	if err != nil {
		return nil, err
	}

	ra, err := net.ResolveUDPAddr(network, bndAddress)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if laddr == nil {
		laddr = &net.UDPAddr{
			IP:   conn.tcpConn.LocalAddr().(*net.TCPAddr).IP,
			Port: conn.tcpConn.LocalAddr().(*net.TCPAddr).Port,
			Zone: conn.tcpConn.LocalAddr().(*net.TCPAddr).Zone,
		}
	}

	udpConn, err := net.DialUDP(network, laddr, ra)
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.underConn = &underAssociate{
		udpConn,
		conn.bufferPool,
		remoteAddress,
	}
	return &Associate{&conn}, nil
}

func (sf *Client) handshake(command byte, addr string) (string, error) {
	methods := statute.MethodNoAuth
	if sf.auth != nil {
		methods = statute.MethodUserPassAuth
	}

	_, err := sf.tcpConn.Write(statute.NewMethodRequest(statute.VersionSocks5, []byte{methods}).Bytes())
	if err != nil {
		return "", err
	}
	reply, err := statute.ParseMethodReply(sf.tcpConn)
	if err != nil {
		return "", err
	}

	if reply.Ver != statute.VersionSocks5 {
		return "", statute.ErrNotSupportVersion
	}
	if reply.Method != methods {
		return "", statute.ErrNotSupportMethod
	}

	if methods == statute.MethodUserPassAuth {
		_, err = sf.tcpConn.Write(statute.NewUserPassRequest(statute.UserPassAuthVersion, []byte(sf.auth.User), []byte(sf.auth.Password)).Bytes())
		if err != nil {
			return "", err
		}

		rsp, err := statute.ParseUserPassReply(sf.tcpConn)
		if err != nil {
			return "", err
		}
		if rsp.Ver != statute.UserPassAuthVersion {
			return "", statute.ErrNotSupportMethod
		}
		if rsp.Status != statute.RepSuccess {
			return "", statute.ErrUserAuthFailed
		}
	}

	a, err := statute.ParseAddrSpec(addr)
	if err != nil {
		return "", err
	}
	reqHead := statute.Request{
		Version:    statute.VersionSocks5,
		Command:    command,
		DstAddress: a,
	}
	if _, err := sf.tcpConn.Write(reqHead.Bytes()); err != nil {
		return "", err
	}

	rspHead, err := statute.ParseReply(sf.tcpConn)
	if err != nil {
		return "", err
	}
	if rspHead.Response != statute.RepSuccess {
		return "", errors.New("host unreachable")
	}
	return rspHead.BndAddress.String(), nil
}

func (sf *Client) dialProxyServer(network string) error {
	conn, err := net.Dial(network, sf.proxyAddr)
	if err != nil {
		return err
	}
	sf.tcpConn = conn.(*net.TCPConn)

	if sf.KeepAlivePeriod != 0 {
		err = sf.tcpConn.SetKeepAlivePeriod(sf.KeepAlivePeriod)
	}
	if err != nil {
		sf.tcpConn.Close()
		return err
	}
	return nil
}

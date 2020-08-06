package ccsocks5

import (
	"errors"
	"net"
	"time"

	"golang.org/x/net/proxy"

	"github.com/thinkgos/go-socks5/bufferpool"
	"github.com/thinkgos/go-socks5/statute"
)

// Client is socks5 client.
type Client struct {
	proxyAddr string
	auth      *proxy.Auth
	// On command UDP, let server control the tcp and udp connection relationship
	tcpConn *net.TCPConn
	net.Conn
	keepAlivePeriod time.Duration
	bufferPool      bufferpool.BufPool
}

// NewClient This is just create a client, you need to use Dial to create conn.
func NewClient(proxyAddr string, opts ...Option) (*Client, error) {
	c := &Client{
		proxyAddr:       proxyAddr,
		keepAlivePeriod: time.Second * 30,
		bufferPool:      bufferpool.NewPool(32 * 1024),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// Close closes the connection.
func (sf *Client) Close() (err error) {
	err = sf.tcpConn.Close()
	if sf.Conn != nil {
		err = sf.Conn.Close()
	}
	return
}

// Dial connects to the address on the named network through proxy , with socks5 handshake.
func (sf *Client) Dial(network, addr string) (net.Conn, error) {
	if network == "tcp" {
		return sf.DialTCP(network, addr)
	}
	if network == "udp" {
		return sf.DialUDP(network, nil, addr)
	}
	return nil, errors.New("not support network")
}

// DialTCP connects to the address on the named network through proxy , with socks5 handshake.
func (sf *Client) DialTCP(network, addr string) (net.Conn, error) {
	conn := *sf // clone a client

	remoteAddress, err := net.ResolveTCPAddr(network, addr)
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
	conn.Conn = &underConnect{
		conn.tcpConn,
		remoteAddress,
	}
	return &Connect{&conn}, nil
}

// DialUDP connects to the address on the named network through proxy , with socks5 handshake.
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
	conn.Conn = &underAssociate{
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

	if sf.keepAlivePeriod != 0 {
		err = sf.tcpConn.SetKeepAlivePeriod(sf.keepAlivePeriod)
	}
	if err != nil {
		sf.tcpConn.Close()
		return err
	}
	return nil
}

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
	proxyConn net.Conn
	// real server connection udp/tcp
	net.Conn
	bufferPool bufferpool.BufPool
}

// NewClient This is just create a client.
// you need to use Dial to create conn.
func NewClient(proxyAddr string, opts ...Option) *Client {
	c := &Client{
		proxyAddr:  proxyAddr,
		bufferPool: bufferpool.NewPool(32 * 1024),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Close closes the connection.
func (sf *Client) Close() (err error) {
	if sf.proxyConn != nil {
		err = sf.proxyConn.Close()
	}
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
	conn.proxyConn, err = net.Dial(network, sf.proxyAddr)
	if err != nil {
		return nil, err
	}

	if _, err := conn.handshake(statute.CommandConnect, addr); err != nil {
		conn.Close()
		return nil, err
	}
	conn.Conn = &underConnect{
		conn.proxyConn.(*net.TCPConn),
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
	conn.proxyConn, err = net.Dial("tcp", sf.proxyAddr)
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
		ad := conn.proxyConn.LocalAddr().(*net.TCPAddr)
		laddr = &net.UDPAddr{
			IP:   ad.IP,
			Port: ad.Port,
			Zone: ad.Zone,
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

	_, err := sf.proxyConn.Write(statute.NewMethodRequest(statute.VersionSocks5, []byte{methods}).Bytes())
	if err != nil {
		return "", err
	}
	reply, err := statute.ParseMethodReply(sf.proxyConn)
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
		_, err = sf.proxyConn.Write(statute.NewUserPassRequest(statute.UserPassAuthVersion,
			[]byte(sf.auth.User), []byte(sf.auth.Password)).Bytes())
		if err != nil {
			return "", err
		}

		rsp, err := statute.ParseUserPassReply(sf.proxyConn)
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
		Version: statute.VersionSocks5,
		Command: command,
		DstAddr: a,
	}
	if _, err := sf.proxyConn.Write(reqHead.Bytes()); err != nil {
		return "", err
	}

	rspHead, err := statute.ParseReply(sf.proxyConn)
	if err != nil {
		return "", err
	}
	if rspHead.Response != statute.RepSuccess {
		return "", errors.New("host unreachable")
	}
	return rspHead.BndAddr.String(), nil
}

// SetKeepAlive sets whether the operating system should send
// keep-alive messages on the connection.
func (sf *Client) SetKeepAlive(keepalive bool) error {
	return sf.proxyConn.(*net.TCPConn).SetKeepAlive(keepalive)
}

// SetKeepAlivePeriod sets period between keep-alives.
func (sf *Client) SetKeepAlivePeriod(d time.Duration) error {
	return sf.proxyConn.(*net.TCPConn).SetKeepAlivePeriod(d)
}

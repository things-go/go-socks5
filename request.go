package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

var (
	unrecognizedAddrType = fmt.Errorf("Unrecognized address type")
)

// AddressRewriter is used to rewrite a destination transparently
type AddressRewriter interface {
	Rewrite(ctx context.Context, request *Request) (context.Context, *AddrSpec)
}

// A Request represents request received by a server
type Request struct {
	Header
	// AuthContext provided during negotiation
	AuthContext *AuthContext
	// AddrSpec of the the network that sent the request
	RemoteAddr *AddrSpec
	// AddrSpec of the desired destination
	DestAddr *AddrSpec
	// AddrSpec of the actual destination (might be affected by rewrite)
	realDestAddr *AddrSpec
	bufConn      io.Reader
}

type conn interface {
	Write([]byte) (int, error)
	RemoteAddr() net.Addr
}

// NewRequest creates a new Request from the tcp connection
func NewRequest(bufConn io.Reader) (*Request, error) {
	/*
		The SOCKS request is formed as follows:
		+----+-----+-------+------+----------+----------+
		|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
		+----+-----+-------+------+----------+----------+
		| 1  |  1  | X'00' |  1   | Variable |    2     |
		+----+-----+-------+------+----------+----------+
	*/
	var hd Header
	var err error

	// Read the version and command
	tmp := make([]byte, headVERLen+headCMDLen)
	if _, err = io.ReadFull(bufConn, tmp); err != nil {
		return nil, fmt.Errorf("failed to get header version and command, %v", err)
	}
	hd.Version = tmp[0]
	hd.Command = tmp[1]

	if hd.Version != socks5Version && hd.Version != socks4Version {
		return nil, fmt.Errorf("unrecognized SOCKS version[%d]", hd.Version)
	}
	if hd.Command != ConnectCommand && hd.Command != BindCommand && hd.Command != AssociateCommand {
		return nil, fmt.Errorf("unrecognized command[%d]", hd.Command)
	}
	if hd.Version == socks4Version && hd.Command == AssociateCommand {
		return nil, fmt.Errorf("wrong version for command")
	}

	if hd.Version == socks4Version {
		// read port and ipv4 ip
		tmp = make([]byte, headPORTLen+net.IPv4len)
		if _, err = io.ReadFull(bufConn, tmp); err != nil {
			return nil, fmt.Errorf("failed to get socks4 header port and ip, %v", err)
		}
		hd.Address.Port = buildPort(tmp[0], tmp[1])
		hd.Address.IP = tmp[2:]
	} else if hd.Version == socks5Version {
		tmp = make([]byte, headRSVLen+headATYPLen)
		if _, err = io.ReadFull(bufConn, tmp); err != nil {
			return nil, fmt.Errorf("failed to get header RSV and address type, %v", err)
		}
		hd.Reserved = tmp[0]
		hd.addrType = tmp[1]
		switch hd.addrType {
		case fqdnAddress:
			if _, err = io.ReadFull(bufConn, tmp[:1]); err != nil {
				return nil, fmt.Errorf("failed to get header, %v", err)
			}
			addrLen := int(tmp[0])
			addr := make([]byte, addrLen+2)
			if _, err = io.ReadFull(bufConn, addr); err != nil {
				return nil, fmt.Errorf("failed to get header, %v", err)
			}
			hd.Address.FQDN = string(addr[:addrLen])
			hd.Address.Port = buildPort(addr[addrLen], addr[addrLen+1])
		case ipv4Address:
			addr := make([]byte, net.IPv4len+2)
			if _, err = io.ReadFull(bufConn, addr); err != nil {
				return nil, fmt.Errorf("failed to get header, %v", err)
			}
			hd.Address.IP = addr[:net.IPv4len]
			hd.Address.Port = buildPort(addr[net.IPv4len], addr[net.IPv4len+1])
		case ipv6Address:
			addr := make([]byte, net.IPv6len+2)
			if _, err = io.ReadFull(bufConn, addr); err != nil {
				return nil, fmt.Errorf("failed to get header, %v", err)
			}
			hd.Address.IP = addr[:net.IPv6len]
			hd.Address.Port = buildPort(addr[net.IPv6len], addr[net.IPv6len+1])
		default:
			return nil, unrecognizedAddrType
		}
	}

	return &Request{
		Header:   hd,
		DestAddr: &hd.Address,
		bufConn:  bufConn,
	}, nil
}

// handleRequest is used for request processing after authentication
func (s *Server) handleRequest(write io.Writer, req *Request) error {
	ctx := context.Background()

	// Resolve the address if we have a FQDN
	dest := req.DestAddr
	if dest.FQDN != "" {
		ctx_, addr, err := s.config.Resolver.Resolve(ctx, dest.FQDN)
		if err != nil {
			if err := sendReply(write, req.Header, hostUnreachable); err != nil {
				return fmt.Errorf("failed to send reply, %v", err)
			}
			return fmt.Errorf("failed to resolve destination[%v], %v", dest.FQDN, err)
		}
		ctx = ctx_
		dest.IP = addr
	}

	// Apply any address rewrites
	req.realDestAddr = req.DestAddr
	if s.config.Rewriter != nil {
		ctx, req.realDestAddr = s.config.Rewriter.Rewrite(ctx, req)
	}

	// Switch on the command
	switch req.Command {
	case ConnectCommand:
		return s.handleConnect(ctx, write, req)
	case BindCommand:
		return s.handleBind(ctx, write, req)
	case AssociateCommand:
		return s.handleAssociate(ctx, write, req)
	default:
		if err := sendReply(write, req.Header, commandNotSupported); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}
		return fmt.Errorf("unsupported command[%v]", req.Command)
	}
}

// handleConnect is used to handle a connect command
func (s *Server) handleConnect(ctx context.Context, writer io.Writer, req *Request) error {
	// Check if this is allowed
	if ctx_, ok := s.config.Rules.Allow(ctx, req); !ok {
		if err := sendReply(writer, req.Header, ruleFailure); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}
		return fmt.Errorf("connect to %v blocked by rules", req.DestAddr)
	} else {
		ctx = ctx_
	}

	// Attempt to connect
	dial := s.config.Dial
	if dial == nil {
		dial = func(ctx context.Context, net_, addr string) (net.Conn, error) {
			return net.Dial(net_, addr)
		}
	}
	target, err := dial(ctx, "tcp", req.realDestAddr.Address())
	if err != nil {
		msg := err.Error()
		resp := hostUnreachable
		if strings.Contains(msg, "refused") {
			resp = connectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = networkUnreachable
		}
		if err := sendReply(writer, req.Header, resp); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}
		return fmt.Errorf("connect to %v failed, %v", req.DestAddr, err)
	}
	defer target.Close()

	// Send success
	if err := sendReply(writer, req.Header, successReply, target.LocalAddr()); err != nil {
		return fmt.Errorf("failed to send reply, %v", err)
	}

	// Start proxying
	errCh := make(chan error, 2)
	go func() { errCh <- s.proxy(target, req.bufConn) }()
	go func() { errCh <- s.proxy(writer, target) }()

	// Wait
	for i := 0; i < 2; i++ {
		e := <-errCh
		if e != nil {
			// return from this function closes target (and conn).
			return e
		}
	}
	return nil
}

// handleBind is used to handle a connect command
func (s *Server) handleBind(ctx context.Context, writer io.Writer, req *Request) error {
	// Check if this is allowed
	if ctx_, ok := s.config.Rules.Allow(ctx, req); !ok {
		if err := sendReply(writer, req.Header, ruleFailure); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}
		return fmt.Errorf("bind to %v blocked by rules", req.DestAddr)
	} else {
		ctx = ctx_
	}

	// TODO: Support bind
	if err := sendReply(writer, req.Header, commandNotSupported); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}
	return nil
}

// handleAssociate is used to handle a connect command
func (s *Server) handleAssociate(ctx context.Context, writer io.Writer, req *Request) error {
	/*
		The SOCKS associate request/response is formed as follows:
		+-----+------+-------+----------+----------+----------+
		| RSV | FRAG |  ATYP | DST.ADDR | DST.PORT |   DATA   |
		+-----+------+-------+----------+----------+----------+
		|  2  |  1   | X'00' |     1    |     2    | Variable |
		+-----+------+-------+----------+----------+----------+
	*/
	// Check if this is allowed
	if ctx_, ok := s.config.Rules.Allow(ctx, req); !ok {
		if err := sendReply(writer, req.Header, ruleFailure); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}
		return fmt.Errorf("associate to %v blocked by rules", req.DestAddr)
	} else {
		ctx = ctx_
	}

	// Attempt to connect
	dial := s.config.Dial
	if dial == nil {
		dial = func(ctx context.Context, net_, addr string) (net.Conn, error) {
			return net.Dial(net_, addr)
		}
	}
	target, err := dial(ctx, "udp", req.realDestAddr.Address())
	if err != nil {
		msg := err.Error()
		resp := hostUnreachable
		if strings.Contains(msg, "refused") {
			resp = connectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = networkUnreachable
		}
		if err := sendReply(writer, req.Header, resp); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}
		return fmt.Errorf("connect to %v failed, %v", req.DestAddr, err)
	}
	defer target.Close()

	targetUdp, ok := target.(*net.UDPConn)
	if !ok {
		if err := sendReply(writer, req.Header, serverFailure); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}
		return fmt.Errorf("dial udp invalid")
	}

	lAddr, _ := net.ResolveUDPAddr("udp", ":0")
	bindLn, err := net.ListenUDP("udp4", lAddr)
	if err != nil {
		if err := sendReply(writer, req.Header, serverFailure); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}
		return fmt.Errorf("listen udp failed, %v", err)
	}

	s.config.Logger.Errorf("target addr %v, listen addr: %s", targetUdp.RemoteAddr(), bindLn.LocalAddr())
	// send BND.ADDR and BND.PORT, client must
	if err = sendReply(writer, req.Header, successReply, bindLn.LocalAddr()); err != nil {
		return fmt.Errorf("failed to send reply, %v", err)
	}

	go func() {
		// read from client and write to remote server
		conns := sync.Map{}
		buf := s.bufferPool.Get()
		defer s.bufferPool.Put(buf)
		for {
			n, srcAddr, err := bindLn.ReadFrom(buf[:cap(buf)])
			if err != nil {
				s.config.Logger.Errorf("read data from bind listen address %s failed, %v", bindLn.LocalAddr(), err)
				return
			}

			// 把消息写给remote sever
			if _, err := targetUdp.Write(buf[:n]); err != nil {
				s.config.Logger.Errorf("write data to remote %s failed, %v", targetUdp.RemoteAddr(), err)
				return
			}

			if _, ok := conns.LoadOrStore(srcAddr.String(), struct{}{}); !ok {
				go func() {
					// read from remote server and write to client
					buf := s.bufferPool.Get()
					defer s.bufferPool.Put(buf)
					for {
						n, _, err := targetUdp.ReadFrom(buf[:cap(buf)])
						if err != nil {
							s.config.Logger.Errorf("read data from remote %s failed, %v", targetUdp.RemoteAddr(), err)
							return
						}

						if _, err := bindLn.WriteTo(buf[:n], srcAddr); err != nil {
							s.config.Logger.Errorf("write data to client %s failed, %v", bindLn.LocalAddr(), err)
							return
						}
					}
				}()
			}
		}
	}()

	buf := s.bufferPool.Get()
	defer func() {
		s.bufferPool.Put(buf)
	}()
	for {
		_, err := req.bufConn.Read(buf)
		if err != nil {
			return err
		}
	}
}

// sendReply is used to send a reply message
func sendReply(w io.Writer, head Header, resp uint8, bindAddr ...net.Addr) error {
	/*
		The SOCKS response is formed as follows:
		+----+-----+-------+------+----------+----------+
		|VER | CMD |  RSV  | ATYP | BND.ADDR | BND.PORT |
		+----+-----+-------+------+----------+----------+
		| 1  |  1  | X'00' |  1   | Variable |    2     |
		+----+-----+-------+------+----------+----------+
	*/

	head.Command = resp

	if len(bindAddr) == 0 {
		head.addrType = ipv4Address
		head.Address.IP = []byte{0, 0, 0, 0}
		head.Address.Port = 0
	} else {
		addrSpec := AddrSpec{}
		if tcpAddr, ok := bindAddr[0].(*net.TCPAddr); ok && tcpAddr != nil {
			addrSpec.IP = tcpAddr.IP
			addrSpec.Port = tcpAddr.Port
		} else if udpAddr, ok := bindAddr[0].(*net.UDPAddr); ok && udpAddr != nil {
			addrSpec.IP = udpAddr.IP
			addrSpec.Port = udpAddr.Port
		} else {
			addrSpec.IP = []byte{0, 0, 0, 0}
			addrSpec.Port = 0
		}
		switch {
		case addrSpec.FQDN != "":
			head.addrType = fqdnAddress
			head.Address.FQDN = addrSpec.FQDN
			head.Address.Port = addrSpec.Port
		case addrSpec.IP.To4() != nil:
			head.addrType = ipv4Address
			head.Address.IP = addrSpec.IP.To4()
			head.Address.Port = addrSpec.Port
		case addrSpec.IP.To16() != nil:
			head.addrType = ipv6Address
			head.Address.IP = addrSpec.IP.To16()
			head.Address.Port = addrSpec.Port
		default:
			return fmt.Errorf("failed to format address[%v]", bindAddr)
		}

	}
	// Send the message
	_, err := w.Write(head.Bytes())
	return err
}

type closeWriter interface {
	CloseWrite() error
}

// proxy is used to suffle data from src to destination, and sends errors
// down a dedicated channel
func (s *Server) proxy(dst io.Writer, src io.Reader) error {
	buf := s.bufferPool.Get()
	defer s.bufferPool.Put(buf)
	_, err := io.CopyBuffer(dst, src, buf[:cap(buf)])
	if tcpConn, ok := dst.(closeWriter); ok {
		tcpConn.CloseWrite()
	}
	return err
}

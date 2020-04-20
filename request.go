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
	hd, err := Parse(bufConn)
	if err != nil {
		return nil, err
	}
	if hd.Command != ConnectCommand && hd.Command != BindCommand && hd.Command != AssociateCommand {
		return nil, fmt.Errorf("unrecognized command[%d]", hd.Command)
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

	s.submit(func() { errCh <- s.proxy(target, req.bufConn) })
	s.submit(func() { errCh <- s.proxy(writer, target) })

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

	bindLn, err := net.ListenUDP("udp", nil)
	if err != nil {
		if err := sendReply(writer, req.Header, serverFailure); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}
		return fmt.Errorf("listen udp failed, %v", err)
	}
	defer bindLn.Close()

	s.config.Logger.Errorf("target addr %v, listen addr: %s", targetUdp.RemoteAddr(), bindLn.LocalAddr())
	// send BND.ADDR and BND.PORT, client must
	if err = sendReply(writer, req.Header, successReply, bindLn.LocalAddr()); err != nil {
		return fmt.Errorf("failed to send reply, %v", err)
	}

	s.submit(func() {
		/*
			The SOCKS UDP request/response is formed as follows:
			+-----+------+-------+----------+----------+----------+
			| RSV | FRAG |  ATYP | DST.ADDR | DST.PORT |   DATA   |
			+-----+------+-------+----------+----------+----------+
			|  2  |  1   | X'00' | Variable |     2    | Variable |
			+-----+------+-------+----------+----------+----------+
		*/
		// read from client and write to remote server
		conns := sync.Map{}
		bufPool := s.bufferPool.Get()
		defer func() {
			targetUdp.Close()
			bindLn.Close()
			s.bufferPool.Put(bufPool)
		}()
		for {
			buf := bufPool[:cap(bufPool)]
			n, srcAddr, err := bindLn.ReadFrom(buf)
			if err != nil {
				s.config.Logger.Errorf("read data from bind listen address %s failed, %v", bindLn.LocalAddr(), err)
				return
			}
			s.config.Logger.Errorf("data length: %d,%d", n, len(buf))
			if n <= 4+net.IPv4len+2 { // no data
				continue
			}
			// ignore RSV,FRAG
			addrType := buf[3]
			addrLen := 0
			headLen := 0
			var addrSpc AddrSpec
			if addrType == ipv4Address {
				headLen = 4 + net.IPv4len + 2
				addrLen = net.IPv4len
				addrSpc.IP = make(net.IP, net.IPv4len)
				copy(addrSpc.IP, buf[4:4+net.IPv4len])
				addrSpc.Port = buildPort(buf[4+net.IPv4len], buf[4+net.IPv4len+1])
			} else if addrType == ipv6Address {
				headLen = 4 + net.IPv6len + 2
				if n <= headLen {
					continue
				}
				addrLen = net.IPv6len
				addrSpc.IP = make(net.IP, net.IPv6len)
				copy(addrSpc.IP, buf[4:4+net.IPv6len])
				addrSpc.Port = buildPort(buf[4+net.IPv6len], buf[4+net.IPv6len+1])
			} else if addrType == fqdnAddress {
				addrLen = int(buf[4])
				headLen = 4 + 1 + addrLen + 2
				if n <= headLen {
					continue
				}
				str := make([]byte, addrLen)
				copy(str, buf[5:5+addrLen])
				addrSpc.FQDN = string(str)
				addrSpc.Port = buildPort(buf[5+addrLen], buf[5+addrLen+1])
			} else {
				continue
			}

			// 把消息写给remote sever
			if _, err := targetUdp.Write(buf[headLen:n]); err != nil {
				s.config.Logger.Errorf("write data to remote %s failed, %v", targetUdp.RemoteAddr(), err)
				return
			}

			if _, ok := conns.LoadOrStore(srcAddr.String(), struct{}{}); !ok {
				s.submit(func() {
					// read from remote server and write to client
					bufPool := s.bufferPool.Get()
					defer func() {
						targetUdp.Close()
						bindLn.Close()
						s.bufferPool.Put(bufPool)
					}()

					for {
						buf := bufPool[:cap(bufPool)]
						n, remote, err := targetUdp.ReadFrom(buf)
						if err != nil {
							s.config.Logger.Errorf("read data from remote %s failed, %v", targetUdp.RemoteAddr(), err)
							return
						}

						tmpBufPool := s.bufferPool.Get()
						proBuf := tmpBufPool
						rAddr, _ := net.ResolveUDPAddr("udp", remote.String())
						hi, lo := breakPort(rAddr.Port)
						if rAddr.IP.To4() != nil {
							proBuf = append(proBuf, []byte{0, 0, 0, ipv4Address}...)
							proBuf = append(proBuf, rAddr.IP.To4()...)
							proBuf = append(proBuf, hi, lo)
						} else if rAddr.IP.To16() != nil {
							proBuf = append(proBuf, []byte{0, 0, 0, ipv6Address}...)
							proBuf = append(proBuf, rAddr.IP.To16()...)
							proBuf = append(proBuf, hi, lo)
						} else { // should never happen
							continue
						}
						proBuf = append(proBuf, buf[:n]...)
						if _, err := bindLn.WriteTo(proBuf, srcAddr); err != nil {
							s.bufferPool.Put(tmpBufPool)
							s.config.Logger.Errorf("write data to client %s failed, %v", bindLn.LocalAddr(), err)
							return
						}
						s.bufferPool.Put(tmpBufPool)
					}
				})
			}
		}
	})

	buf := s.bufferPool.Get()
	defer func() {
		s.bufferPool.Put(buf)
	}()
	for {
		_, err := req.bufConn.Read(buf[:cap(buf)])
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

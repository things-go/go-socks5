package socks5

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
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
	// Protocol version
	Version uint8
	// Requested command
	Command uint8
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
func NewRequest(r io.Reader) (*Request, error) {
	var hd Header
	var err error

	h := make([]byte, 5)
	bufConn := bufio.NewReader(r)
	if h, err = bufConn.Peek(5); err != nil {
		return nil, fmt.Errorf("failed to get header, %w", err)
	}

	hd.Version = h[0]
	hd.Command = h[1]

	if hd.Version != socks5Version && hd.Version != socks4Version {
		return nil, fmt.Errorf("unrecognized SOCKS version[%d]", hd.Version)
	}
	if hd.Command != ConnectCommand && hd.Command != BindCommand && hd.Command != AssociateCommand {
		return nil, fmt.Errorf("unrecognized command[%d]", hd.Command)
	}
	if hd.Version == socks4Version && hd.Command == AssociateCommand {
		return nil, fmt.Errorf("wrong version for command")
	}

	hd.headerLen = reqVersionLen + reqCommandLen + reqPortLen
	if hd.Version == socks4Version {
		hd.addrLen = reqIPv4Addr
	} else if hd.Version == socks5Version {
		hd.Reserved = h[2]
		hd.addrType = h[3]
		hd.headerLen += reqReservedLen + reqAddrTypeLen
		switch hd.addrType {
		case fqdnAddress:
			hd.headerLen += 1
			hd.addrLen = int(h[4])
		case ipv4Address:
			hd.addrLen = reqIPv4Addr
		case ipv6Address:
			hd.addrLen = reqIPv6Addr
		default:
			return nil, unrecognizedAddrType
		}
	}
	hd.headerLen += hd.addrLen
	var bHeader []byte
	if bHeader, err = bufConn.Peek(hd.headerLen); err != nil {
		return nil, fmt.Errorf("failed to get header address, %w", err)
	}

	switch hd.addrType {
	case ipv4Address:
		hd.Address.IP = bHeader[reqAddrBytePos : reqAddrBytePos+reqIPv4Addr]
		if hd.Version == socks4Version {
			hd.Address.Port = buildPort(bHeader[req4PortBytePos], bHeader[req4PortBytePos+1])
		} else if hd.Version == socks5Version {
			hd.Address.Port = buildPort(bHeader[hd.headerLen-2], bHeader[hd.headerLen-1])
		}
	case ipv6Address:
		hd.Address.IP = bHeader[reqAddrBytePos : reqAddrBytePos+reqIPv6Addr]
		hd.Address.Port = buildPort(bHeader[hd.headerLen-2], bHeader[hd.headerLen-1])
	case fqdnAddress:
		hd.Address.FQDN = string(bHeader[reqAddrBytePos : hd.headerLen-reqPortLen])
		hd.Address.Port = buildPort(bHeader[hd.headerLen-2], bHeader[hd.headerLen-1])
	}
	if _, err := bufConn.Discard(hd.headerLen); err != nil {
		return nil, fmt.Errorf("failed to discard header, %w", err)
	}
	return &Request{
		Version:  hd.Version,
		Command:  hd.Command,
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
			if err := sendReply(write, hostUnreachable, nil); err != nil {
				return fmt.Errorf("failed to send reply, %w", err)
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
		if err := sendReply(write, commandNotSupported, nil); err != nil {
			return fmt.Errorf("failed to send reply, %w", err)
		}
		return fmt.Errorf("unsupported command[%v]", req.Command)
	}
}

// handleConnect is used to handle a connect command
func (s *Server) handleConnect(ctx context.Context, w io.Writer, req *Request) error {
	// Check if this is allowed
	if ctx_, ok := s.config.Rules.Allow(ctx, req); !ok {
		if err := sendReply(w, ruleFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply, %w", err)
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
		if err := sendReply(w, resp, nil); err != nil {
			return fmt.Errorf("failed to send reply, %w", err)
		}
		return fmt.Errorf("connect to %v failed, %w", req.DestAddr, err)
	}
	defer target.Close()

	// Send success
	if err := sendReply(w, successReply, addrSpecFromNetAddr(target.LocalAddr())); err != nil {
		return fmt.Errorf("failed to send reply, %w", err)
	}

	// Start proxying
	errCh := make(chan error, 2)
	go proxy(target, req.bufConn, errCh)
	go proxy(w, target, errCh)

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
func (s *Server) handleBind(ctx context.Context, conn io.Writer, req *Request) error {
	// Check if this is allowed
	if ctx_, ok := s.config.Rules.Allow(ctx, req); !ok {
		if err := sendReply(conn, ruleFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply, %w", err)
		}
		return fmt.Errorf("bind to %v blocked by rules", req.DestAddr)
	} else {
		ctx = ctx_
	}

	// TODO: Support bind
	if err := sendReply(conn, commandNotSupported, nil); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}
	return nil
}

// handleAssociate is used to handle a connect command
func (s *Server) handleAssociate(ctx context.Context, conn io.Writer, req *Request) error {
	// Check if this is allowed
	if ctx_, ok := s.config.Rules.Allow(ctx, req); !ok {
		if err := sendReply(conn, ruleFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}
		return fmt.Errorf("associate to %v blocked by rules", req.DestAddr)
	} else {
		ctx = ctx_
	}

	// TODO: Support associate
	if err := sendReply(conn, commandNotSupported, nil); err != nil {
		return fmt.Errorf("failed to send reply, %w", err)
	}
	return nil
}

func addrSpecFromNetAddr(addr net.Addr) *AddrSpec {
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return &AddrSpec{IP: tcpAddr.IP, Port: tcpAddr.Port}
	}
	return nil
}

// sendReply is used to send a reply message
func sendReply(w io.Writer, resp uint8, addr *AddrSpec) error {
	var head Header
	// Format the address
	var addrBody []byte
	var addrPort uint16

	head.Version = socks5Version
	head.Command = resp
	head.Reserved = 0
	switch {
	case addr == nil:
		head.addrType = ipv4Address
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.FQDN != "":
		head.addrType = fqdnAddress
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		head.addrType = ipv4Address
		addrBody = addr.IP.To4()
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		head.addrType = ipv6Address
		addrBody = addr.IP.To16()
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("failed to format address[%v]", addr)
	}

	// Format the message
	msg := make([]byte, 0, 6+len(addrBody))
	msg = append(msg, head.Version, head.Command, head.Reserved, head.addrType)
	msg = append(msg, addrBody...)
	msg = append(msg, byte(addrPort>>8), byte(addrPort&0xff))

	// Send the message
	_, err := w.Write(msg)
	return err
}

type closeWriter interface {
	CloseWrite() error
}

// proxy is used to suffle data from src to destination, and sends errors
// down a dedicated channel
func proxy(dst io.Writer, src io.Reader, errCh chan error) {
	_, err := io.Copy(dst, src)
	if tcpConn, ok := dst.(closeWriter); ok {
		tcpConn.CloseWrite()
	}
	errCh <- err
}

package socks5

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
)

const (
	// protocol version
	socks4Version = uint8(4)
	socks5Version = uint8(5)
	// request command
	ConnectCommand   = uint8(1)
	BindCommand      = uint8(2)
	AssociateCommand = uint8(3) // udp associate
	// address type
	ipv4Address = uint8(1)
	fqdnAddress = uint8(3) // domain
	ipv6Address = uint8(4)
)

//
const (
	successReply uint8 = iota
	serverFailure
	ruleFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
	// 0x09 - 0xff unassigned
)

const (
	// common fields
	reqProtocolVersionBytePos = uint8(0) // proto version pos
	reqCommandBytePos         = uint8(1)
	reqAddrBytePos            = uint8(4)
	reqStartLen               = uint8(4)

	reqVersionLen  = 1
	reqCommandLen  = 1
	reqPortLen     = 2
	reqReservedLen = 1
	reqAddrTypeLen = 1
	reqIPv4Addr    = 4
	reqIPv6Addr    = 8
	reqFQDNAddr    = 249

	//position settings for socks4
	req4PortBytePos = uint8(2)
)

// AddressRewriter is used to rewrite a destination transparently
type AddressRewriter interface {
	Rewrite(ctx context.Context, request *Request) (context.Context, *AddrSpec)
}

// AddrSpec is used to return the target AddrSpec
// which may be specified as IPv4, IPv6, or a FQDN
type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

func (a *AddrSpec) String() string {
	if a.FQDN != "" {
		return fmt.Sprintf("%s (%s):%d", a.FQDN, a.IP, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

// Address returns a string suitable to dial; prefer returning IP-based
// address, fallback to FQDN
func (a AddrSpec) Address() string {
	if 0 != len(a.IP) {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(a.FQDN, strconv.Itoa(a.Port))
}

// Header represents the SOCKS5/SOCKS4 header, it contains everything that is not payload
type Header struct {
	// Version of socks protocol for message
	Version uint8
	// Socks Command "connect","bind","associate"
	Command uint8
	// Reserved byte
	Reserved uint8 // only socks5 support
	// Address in socks message
	Address AddrSpec
	// private stuff set when Header parsed
	addrType  uint8
	addrLen   int
	headerLen int
}

func (h Header) Bytes() (b []byte) {
	b = append(b, h.Version)
	b = append(b, h.Command)
	hiPort, loPort := breakPort(h.Address.Port)
	if h.Version == socks4Version {
		b = append(b, hiPort, loPort)
		b = append(b, h.Address.IP...)
	} else if h.Version == socks5Version {
		b = append(b, h.Reserved)
		b = append(b, h.addrType)
		if h.addrType == fqdnAddress {
			b = append(b, []byte(h.Address.FQDN)...)
		} else {
			b = append(b, h.Address.IP...)
		}
		b = append(b, hiPort, loPort)
	}
	return b
}

func Parse(r io.Reader) (hd Header, err error) {
	h := make([]byte, 5)
	bufConn := bufio.NewReader(r)
	if h, err = bufConn.Peek(5); err != nil {
		return hd, fmt.Errorf("failed to get header: %v", err)
	}

	hd.Version = h[0]
	hd.Command = h[1]

	if hd.Version != socks5Version && hd.Version != socks4Version {
		return hd, fmt.Errorf("unrecognized SOCKS version")
	}
	if hd.Command != ConnectCommand && hd.Command != BindCommand && hd.Command != AssociateCommand {
		return hd, fmt.Errorf("unrecognized command")
	}
	if hd.Version == socks4Version && hd.Command == AssociateCommand {
		return hd, fmt.Errorf("wrong version for command")
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
			return hd, unrecognizedAddrType
		}
	}
	hd.headerLen += hd.addrLen

	bHeader := make([]byte, hd.headerLen)
	if _, err = io.ReadAtLeast(bufConn, bHeader, hd.headerLen); err != nil {
		return hd, fmt.Errorf("failed to get header address: %v", err)
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
	log.Printf("%+v", hd)
	return hd, nil
	//payload = make([]byte, 4)
	//if _, err := bufConn.Read(payload); err != nil {
	//	return hd, payload, fmt.Errorf("failed read payload: %v", err)
	//}
	//return hd, payload, nil
}

func buildPort(hi, lo byte) int {
	return (int(hi) << 8) | int(lo)
}

func breakPort(port int) (hi, lo byte) {
	return byte(port >> 8), byte(port)
}

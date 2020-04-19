package socks5

import (
	"fmt"
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
	addrType uint8
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

func buildPort(hi, lo byte) int {
	return (int(hi) << 8) | int(lo)
}

func breakPort(port int) (hi, lo byte) {
	return byte(port >> 8), byte(port)
}

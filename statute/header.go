package statute

import (
	"fmt"
	"io"
	"net"
)

// Header represents the SOCKS4/SOCKS5 head len defined
const (
	headerVERLen  = 1
	headerCMDLen  = 1
	headerRSVLen  = 1 // only socks5 support
	headerATYPLen = 1
	headerPORTLen = 2
)

// Header represents the SOCKS4/SOCKS5 header, it contains everything that is not payload
// The SOCKS4 request/response is formed as follows:
//	+-----+-----+------+------+
//	| VER | CMD | PORT | IPV4 |
//	+-----+-----+------+------+
//	|  1  |  1  |  2   |  2   |
//	+-----+-----+------+------+
// The SOCKS5 request/response is formed as follows:
//	+-----+-----+-------+------+----------------+----------------+
//	| VER | CMD |  RSV  | ATYP | [DST/BND].ADDR | [DST/BND].PORT |
//	+-----+-----+-------+------+----------------+----------------+
//	|  1  |  1  | X'00' |  1   |    Variable    |       2        |
//	+-----+-----+-------+------+----------------+----------------+
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
	AddrType uint8
}

// ParseHeader to header from io.Reader
func ParseHeader(r io.Reader) (hd Header, err error) {
	// Read the version and command
	tmp := make([]byte, headerVERLen+headerCMDLen)
	if _, err = io.ReadFull(r, tmp); err != nil {
		return hd, fmt.Errorf("failed to get header version and command, %v", err)
	}
	hd.Version = tmp[0]
	hd.Command = tmp[1]

	if hd.Version != VersionSocks5 && hd.Version != VersionSocks4 {
		return hd, fmt.Errorf("unrecognized SOCKS version[%d]", hd.Version)
	}

	if hd.Version == VersionSocks4 && hd.Command == CommandAssociate {
		return hd, fmt.Errorf("SOCKS4 version not support command: associate")
	}

	if hd.Version == VersionSocks5 {
		tmp = make([]byte, headerRSVLen+headerATYPLen)
		if _, err = io.ReadFull(r, tmp); err != nil {
			return hd, fmt.Errorf("failed to get header RSV and address type, %v", err)
		}
		hd.Reserved = tmp[0]
		hd.AddrType = tmp[1]
		switch hd.AddrType {
		case ATYPDomain:
			if _, err = io.ReadFull(r, tmp[:1]); err != nil {
				return hd, fmt.Errorf("failed to get header, %v", err)
			}
			domainLen := int(tmp[0])
			addr := make([]byte, domainLen+headerPORTLen)
			if _, err = io.ReadFull(r, addr); err != nil {
				return hd, fmt.Errorf("failed to get header, %v", err)
			}
			hd.Address.FQDN = string(addr[:domainLen])
			hd.Address.Port = BuildPort(addr[domainLen], addr[domainLen+1])
		case ATYPIPv4:
			addr := make([]byte, net.IPv4len+2)
			if _, err = io.ReadFull(r, addr); err != nil {
				return hd, fmt.Errorf("failed to get header, %v", err)
			}
			hd.Address.IP = net.IPv4(addr[0], addr[1], addr[2], addr[3])
			hd.Address.Port = BuildPort(addr[net.IPv4len], addr[net.IPv4len+1])
		case ATYPIPv6:
			addr := make([]byte, net.IPv6len+2)
			if _, err = io.ReadFull(r, addr); err != nil {
				return hd, fmt.Errorf("failed to get header, %v", err)
			}
			hd.Address.IP = addr[:net.IPv6len]
			hd.Address.Port = BuildPort(addr[net.IPv6len], addr[net.IPv6len+1])
		default:
			return hd, ErrUnrecognizedAddrType
		}
	} else { // Socks4
		// read port and ipv4 ip
		tmp = make([]byte, headerPORTLen+net.IPv4len)
		if _, err = io.ReadFull(r, tmp); err != nil {
			return hd, fmt.Errorf("failed to get socks4 header port and ip, %v", err)
		}
		hd.Address.Port = BuildPort(tmp[0], tmp[1])
		hd.Address.IP = net.IPv4(tmp[2], tmp[3], tmp[4], tmp[5])
	}
	return hd, nil
}

// Bytes returns a slice of header
func (h Header) Bytes() (b []byte) {
	hiPort, loPort := BreakPort(h.Address.Port)
	if h.Version == VersionSocks4 {
		b = make([]byte, 0, headerVERLen+headerCMDLen+headerPORTLen+net.IPv4len)
		b = append(b, h.Version)
		b = append(b, h.Command)
		b = append(b, hiPort, loPort)
		b = append(b, h.Address.IP.To4()...)
	} else if h.Version == VersionSocks5 {
		length := headerVERLen + headerCMDLen + headerRSVLen + headerATYPLen + headerPORTLen
		if h.AddrType == ATYPDomain {
			length += 1 + len(h.Address.FQDN)
		} else if h.AddrType == ATYPIPv4 {
			length += net.IPv4len
		} else if h.AddrType == ATYPIPv6 {
			length += net.IPv6len
		}
		b = make([]byte, 0, length)
		b = append(b, h.Version)
		b = append(b, h.Command)
		b = append(b, h.Reserved)
		b = append(b, h.AddrType)
		if h.AddrType == ATYPDomain {
			b = append(b, byte(len(h.Address.FQDN)))
			b = append(b, []byte(h.Address.FQDN)...)
		} else if h.AddrType == ATYPIPv4 {
			b = append(b, h.Address.IP.To4()...)
		} else if h.AddrType == ATYPIPv6 {
			b = append(b, h.Address.IP.To16()...)
		}
		b = append(b, hiPort, loPort)
	}
	return b
}

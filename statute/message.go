package statute

import (
	"fmt"
	"io"
	"net"
)

// Request represents the SOCKS5 request, it contains everything that is not payload
// The SOCKS5 request is formed as follows:
//	+-----+-----+-------+------+----------+----------+
//	| VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//	+-----+-----+-------+------+----------+----------+
//	|  1  |  1  | X'00' |  1   | Variable |    2     |
//	+-----+-----+-------+------+----------+----------+
type Request struct {
	// Version of socks protocol for message
	Version byte
	// Socks Command "connect","bind","associate"
	Command byte
	// Reserved byte
	Reserved byte
	// DstAddress in socks message
	DstAddress AddrSpec
}

// ParseRequest to request from io.Reader
func ParseRequest(r io.Reader) (req Request, err error) {
	// Read the version and command
	tmp := []byte{0, 0}
	if _, err = io.ReadFull(r, tmp); err != nil {
		return req, fmt.Errorf("failed to get request version and command, %v", err)
	}
	req.Version, req.Command = tmp[0], tmp[1]
	if req.Version != VersionSocks5 {
		return req, fmt.Errorf("unrecognized SOCKS version[%d]", req.Version)
	}

	// Read reserved and address type
	if _, err = io.ReadFull(r, tmp); err != nil {
		return req, fmt.Errorf("failed to get request RSV and address type, %v", err)
	}
	req.Reserved, req.DstAddress.AddrType = tmp[0], tmp[1]

	switch req.DstAddress.AddrType {
	case ATYPIPv4:
		addr := make([]byte, net.IPv4len+2)
		if _, err = io.ReadFull(r, addr); err != nil {
			return req, fmt.Errorf("failed to get request, %v", err)
		}
		req.DstAddress.IP = net.IPv4(addr[0], addr[1], addr[2], addr[3])
		req.DstAddress.Port = buildPort(addr[net.IPv4len], addr[net.IPv4len+1])
	case ATYPIPv6:
		addr := make([]byte, net.IPv6len+2)
		if _, err = io.ReadFull(r, addr); err != nil {
			return req, fmt.Errorf("failed to get request, %v", err)
		}
		req.DstAddress.IP = addr[:net.IPv6len]
		req.DstAddress.Port = buildPort(addr[net.IPv6len], addr[net.IPv6len+1])
	case ATYPDomain:
		if _, err = io.ReadFull(r, tmp[:1]); err != nil {
			return req, fmt.Errorf("failed to get request, %v", err)
		}
		domainLen := int(tmp[0])
		addr := make([]byte, domainLen+2)
		if _, err = io.ReadFull(r, addr); err != nil {
			return req, fmt.Errorf("failed to get request, %v", err)
		}
		req.DstAddress.FQDN = string(addr[:domainLen])
		req.DstAddress.Port = buildPort(addr[domainLen], addr[domainLen+1])
	default:
		return req, ErrUnrecognizedAddrType
	}
	return req, nil
}

// Bytes returns a slice of request
func (h Request) Bytes() (b []byte) {
	var addr []byte

	length := 6
	if h.DstAddress.AddrType == ATYPIPv4 {
		length += net.IPv4len
		addr = h.DstAddress.IP.To4()
	} else if h.DstAddress.AddrType == ATYPIPv6 {
		length += net.IPv6len
		addr = h.DstAddress.IP.To16()
	} else { //ATYPDomain
		length += 1 + len(h.DstAddress.FQDN)
		addr = []byte(h.DstAddress.FQDN)
	}

	b = make([]byte, 0, length)
	b = append(b, h.Version, h.Command, h.Reserved, h.DstAddress.AddrType)
	if h.DstAddress.AddrType == ATYPDomain {
		b = append(b, byte(len(h.DstAddress.FQDN)))
	}
	b = append(b, addr...)
	hiPort, loPort := breakPort(h.DstAddress.Port)
	b = append(b, hiPort, loPort)
	return b
}

// Reply represents the SOCKS5 reply, it contains everything that is not payload
// The SOCKS5 response is formed as follows:
//	+-----+-----+-------+------+----------+-----------+
//	| VER | REP |  RSV  | ATYP | BND.ADDR | BND].PORT |
//	+-----+-----+-------+------+----------+----------+
//	|  1  |  1  | X'00' |  1   | Variable |    2     |
//	+-----+-----+-------+------+----------+----------+
type Reply struct {
	// Version of socks protocol for message
	Version byte
	// Socks Response status"
	Response byte
	// Reserved byte
	Reserved byte
	// Bind Address in socks message
	BndAddress AddrSpec
}

// Bytes returns a slice of request
func (h Reply) Bytes() (b []byte) {
	var addr []byte

	length := 6
	if h.BndAddress.AddrType == ATYPIPv4 {
		length += net.IPv4len
		addr = h.BndAddress.IP.To4()
	} else if h.BndAddress.AddrType == ATYPIPv6 {
		length += net.IPv6len
		addr = h.BndAddress.IP.To16()
	} else { //ATYPDomain
		length += 1 + len(h.BndAddress.FQDN)
		addr = []byte(h.BndAddress.FQDN)
	}

	b = make([]byte, 0, length)
	b = append(b, h.Version, h.Response, h.Reserved, h.BndAddress.AddrType)
	if h.BndAddress.AddrType == ATYPDomain {
		b = append(b, byte(len(h.BndAddress.FQDN)))
	}
	b = append(b, addr...)
	hiPort, loPort := breakPort(h.BndAddress.Port)
	b = append(b, hiPort, loPort)
	return b
}

// ParseReply parse to reply from io.Reader
func ParseReply(r io.Reader) (rep Reply, err error) {
	// Read the version and command
	tmp := []byte{0, 0}
	if _, err = io.ReadFull(r, tmp); err != nil {
		return rep, fmt.Errorf("failed to get request version and command, %v", err)
	}
	rep.Version, rep.Response = tmp[0], tmp[1]
	if rep.Version != VersionSocks5 {
		return rep, fmt.Errorf("unrecognized SOCKS version[%d]", rep.Version)
	}
	// Read reserved and address type
	if _, err = io.ReadFull(r, tmp); err != nil {
		return rep, fmt.Errorf("failed to get request RSV and address type, %v", err)
	}
	rep.Reserved, rep.BndAddress.AddrType = tmp[0], tmp[1]

	switch rep.BndAddress.AddrType {
	case ATYPDomain:
		if _, err = io.ReadFull(r, tmp[:1]); err != nil {
			return rep, fmt.Errorf("failed to get request, %v", err)
		}
		domainLen := int(tmp[0])
		addr := make([]byte, domainLen+2)
		if _, err = io.ReadFull(r, addr); err != nil {
			return rep, fmt.Errorf("failed to get request, %v", err)
		}
		rep.BndAddress.FQDN = string(addr[:domainLen])
		rep.BndAddress.Port = buildPort(addr[domainLen], addr[domainLen+1])
	case ATYPIPv4:
		addr := make([]byte, net.IPv4len+2)
		if _, err = io.ReadFull(r, addr); err != nil {
			return rep, fmt.Errorf("failed to get request, %v", err)
		}
		rep.BndAddress.IP = net.IPv4(addr[0], addr[1], addr[2], addr[3])
		rep.BndAddress.Port = buildPort(addr[net.IPv4len], addr[net.IPv4len+1])
	case ATYPIPv6:
		addr := make([]byte, net.IPv6len+2)
		if _, err = io.ReadFull(r, addr); err != nil {
			return rep, fmt.Errorf("failed to get request, %v", err)
		}
		rep.BndAddress.IP = addr[:net.IPv6len]
		rep.BndAddress.Port = buildPort(addr[net.IPv6len], addr[net.IPv6len+1])
	default:
		return rep, ErrUnrecognizedAddrType
	}
	return rep, nil
}

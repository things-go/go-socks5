package statute

import (
	"errors"
	"math"
	"net"
)

// Datagram udp packet
// The SOCKS UDP request/response is formed as follows:
// +-----+------+-------+----------+----------+----------+
// | RSV | FRAG |  ATYP | DST.ADDR | DST.PORT |   DATA   |
// +-----+------+-------+----------+----------+----------+
// |  2  |  1   | X'00' | Variable |     2    | Variable |
// +-----+------+-------+----------+----------+----------+
type Datagram struct {
	RSV     uint16
	Frag    byte
	DstAddr AddrSpec
	Data    []byte
}

// NewDatagram new packet with dest addr and data
func NewDatagram(destAddr string, data []byte) (p Datagram, err error) {
	p.DstAddr, err = ParseAddrSpec(destAddr)
	if err != nil {
		return
	}
	if p.DstAddr.AddrType == ATYPDomain && len(p.DstAddr.FQDN) > math.MaxUint8 {
		err = errors.New("destination host name too long")
		return
	}
	p.RSV, p.Frag, p.Data = 0, 0, data
	return
}

// ParseDatagram parse to datagram from bytes
func ParseDatagram(b []byte) (da Datagram, err error) {
	if len(b) < 4+net.IPv4len+2 { // no enough data
		err = errors.New("datagram to short")
		return
	}
	// ignore RSV
	// get FRAG and Address  type
	da.RSV, da.Frag, da.DstAddr.AddrType = 0, b[2], b[3]

	headLen := 4
	switch da.DstAddr.AddrType {
	case ATYPIPv4:
		headLen += net.IPv4len + 2
		da.DstAddr.IP = net.IPv4(b[4], b[5], b[6], b[7])
		da.DstAddr.Port = buildPort(b[4+net.IPv4len], b[4+net.IPv4len+1])
	case ATYPIPv6:
		headLen += net.IPv6len + 2
		if len(b) <= headLen {
			err = errors.New("datagram to short")
			return
		}

		da.DstAddr.IP = b[4 : 4+net.IPv6len]
		da.DstAddr.Port = buildPort(b[4+net.IPv6len], b[4+net.IPv6len+1])
	case ATYPDomain:
		addrLen := int(b[4])
		headLen += 1 + addrLen + 2
		if len(b) <= headLen {
			err = errors.New("datagram to short")
			return
		}
		str := make([]byte, addrLen)
		copy(str, b[5:5+addrLen])
		da.DstAddr.FQDN = string(str)
		da.DstAddr.Port = buildPort(b[5+addrLen], b[5+addrLen+1])
	default:
		err = ErrUnrecognizedAddrType
		return
	}
	da.Data = b[headLen:]
	return
}

// Header returns s slice of datagram header except data
func (sf *Datagram) Header() []byte {
	return sf.values(false)
}

// Bytes datagram to bytes
func (sf *Datagram) Bytes() []byte {
	return sf.values(true)
}

func (sf *Datagram) values(hasData bool) (bs []byte) {
	var addr []byte

	length := 6
	switch sf.DstAddr.AddrType {
	case ATYPIPv4:
		length += net.IPv4len
		addr = sf.DstAddr.IP.To4()
	case ATYPIPv6:
		length += net.IPv6len
		addr = sf.DstAddr.IP.To16()
	case ATYPDomain:
		length += 1 + len(sf.DstAddr.FQDN)
		addr = []byte(sf.DstAddr.FQDN)
	}
	if hasData {
		bs = make([]byte, 0, length+len(sf.Data))
	} else {
		bs = make([]byte, 0, length)
	}

	bs = append(bs, byte(sf.RSV<<8), byte(sf.RSV), sf.Frag, sf.DstAddr.AddrType)
	if sf.DstAddr.AddrType == ATYPDomain {
		bs = append(bs, byte(len(sf.DstAddr.FQDN)))
	}
	bs = append(bs, addr...)
	hi, lo := breakPort(sf.DstAddr.Port)
	bs = append(bs, hi, lo)
	if hasData {
		bs = append(bs, sf.Data...)
	}
	return
}

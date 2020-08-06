package statute

import (
	"errors"
	"math"
	"net"
)

// The SOCKS UDP request/response is formed as follows:
// +-----+------+-------+----------+----------+----------+
// | RSV | FRAG |  ATYP | DST.ADDR | DST.PORT |   DATA   |
// +-----+------+-------+----------+----------+----------+
// |  2  |  1   | X'00' | Variable |     2    | Variable |
// +-----+------+-------+----------+----------+----------+
// Datagram udp packet
type Datagram struct {
	RSV     uint16
	Frag    uint8
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
	p.RSV = 0
	p.Frag = 0
	p.Data = data
	return
}

// ParseRequest parse to packet
func ParseDatagram(b []byte) (da Datagram, err error) {
	if len(b) < 4+net.IPv4len+2 { // no data
		err = errors.New("datagram to short")
		return
	}
	// ignore RSV
	da.RSV = 0
	// FRAG
	da.Frag = b[2]
	da.DstAddr.AddrType = b[3]
	headLen := 4
	switch da.DstAddr.AddrType {
	case ATYPIPv4:
		headLen += net.IPv4len + 2
		da.DstAddr.IP = net.IPv4(b[4], b[5], b[6], b[7])
		da.DstAddr.Port = BuildPort(b[4+net.IPv4len], b[4+net.IPv4len+1])
	case ATYPIPv6:
		headLen += net.IPv6len + 2
		if len(b) <= headLen {
			err = errors.New("datagram to short")
			return
		}

		da.DstAddr.IP = net.IP{b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]}
		da.DstAddr.Port = BuildPort(b[4+net.IPv6len], b[4+net.IPv6len+1])
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
		da.DstAddr.Port = BuildPort(b[5+addrLen], b[5+addrLen+1])
	default:
		err = ErrUnrecognizedAddrType
		return
	}
	da.Data = b[headLen:]
	return
}

// Request returns s slice of datagram header except data
func (sf *Datagram) Header() []byte {
	bs := make([]byte, 0, 32)
	bs = append(bs, []byte{byte(sf.RSV << 8), byte(sf.RSV), sf.Frag}...)
	switch sf.DstAddr.AddrType {
	case ATYPIPv4:
		bs = append(bs, ATYPIPv4)
		bs = append(bs, sf.DstAddr.IP.To4()...)
	case ATYPIPv6:
		bs = append(bs, ATYPIPv6)
		bs = append(bs, sf.DstAddr.IP.To16()...)
	case ATYPDomain:
		bs = append(bs, ATYPDomain, byte(len(sf.DstAddr.FQDN)))
		bs = append(bs, []byte(sf.DstAddr.FQDN)...)
	}
	hi, lo := BreakPort(sf.DstAddr.Port)
	bs = append(bs, hi, lo)
	return bs
}

func (sf *Datagram) Bytes() []byte {
	return append(sf.Header(), sf.Data...)
}

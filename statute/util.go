package statute

import (
	"fmt"
	"net"
	"strconv"
)

// AddrSpec is used to return the target AddrSpec
// which may be specified as IPv4, IPv6, or a FQDN
type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
	// private stuff set when Request parsed
	AddrType byte
}

// String returns a string suitable to dial; prefer returning IP-based
// address, fallback to FQDN
func (a *AddrSpec) String() string {
	if 0 != len(a.IP) {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(a.FQDN, strconv.Itoa(a.Port))
}

// Address returns a string which may be specified
// if IPv4/IPv6 will return < ip:port >
// if FQDN will return < domain ip:port >
// Note: do not used to dial, Please use String
func (a AddrSpec) Address() string {
	if a.FQDN != "" {
		return fmt.Sprintf("%s (%s):%d", a.FQDN, a.IP, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

// ParseAddrSpec parse address to the AddrSpec address
func ParseAddrSpec(address string) (as AddrSpec, err error) {
	var host, port string

	host, port, err = net.SplitHostPort(address)
	if err != nil {
		return
	}
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		as.AddrType, as.IP = ATYPIPv4, ip
	} else if ip6 := ip.To16(); ip6 != nil {
		as.AddrType, as.IP = ATYPIPv6, ip
	} else {
		as.AddrType, as.FQDN = ATYPDomain, host
	}
	as.Port, err = strconv.Atoi(port)
	return
}

func buildPort(hi, lo byte) int        { return (int(hi) << 8) | int(lo) }
func breakPort(port int) (hi, lo byte) { return byte(port >> 8), byte(port) }

package statute

import (
	"net"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddrSpecAddr(t *testing.T) {
	addr1 := AddrSpec{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 8080,
	}
	assert.Equal(t, "127.0.0.1:8080", addr1.String())
	assert.Equal(t, "127.0.0.1:8080", addr1.Address())

	addr2 := AddrSpec{
		FQDN: "localhost",
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 8080,
	}
	assert.Equal(t, "127.0.0.1:8080", addr2.String())
	assert.Equal(t, "localhost (127.0.0.1):8080", addr2.Address())

	addr3 := AddrSpec{
		FQDN: "localhost",
		Port: 8080,
	}
	assert.Equal(t, "localhost:8080", addr3.String())
}

func TestParseAddrSpec(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantA   AddrSpec
		wantErr bool
	}{
		{
			"IPv4",
			"127.0.0.1:8080",
			AddrSpec{
				IP:       net.IPv4(127, 0, 0, 1),
				Port:     8080,
				AddrType: ATYPIPv4,
			},
			false,
		},
		{
			"IPv6",
			"[::1]:8080",
			AddrSpec{
				IP:       net.IPv6loopback,
				Port:     8080,
				AddrType: ATYPIPv6,
			},
			false,
		},
		{
			"FQDN",
			"localhost:8080",
			AddrSpec{
				FQDN:     "localhost",
				Port:     8080,
				AddrType: ATYPDomain,
			},
			false,
		},
		{
			"invalid address,miss port",
			"localhost",
			AddrSpec{},
			true,
		},
		{
			"invalid port",
			"localhost:abc",
			AddrSpec{},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotA, err := ParseAddrSpec(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAddrSpec() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotA, tt.wantA) {
				t.Errorf("ParseAddrSpec() gotA = %v, want %v", gotA, tt.wantA)
			}
		})
	}
}

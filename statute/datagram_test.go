package statute

import (
	"net"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDatagram(t *testing.T) {
	_, err := NewDatagram("localhost", nil)
	require.Error(t, err)

	_, err = NewDatagram("localhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhost"+
		"localhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhost"+
		"localhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhost:8080", nil)
	require.Error(t, err)

	datagram, err := NewDatagram("localhost:8080", []byte{1, 2, 3})
	require.NoError(t, err)
	require.Equal(t, Datagram{
		0, 0, AddrSpec{
			FQDN:     "localhost",
			Port:     8080,
			AddrType: ATYPDomain,
		},
		[]byte{1, 2, 3},
	}, datagram)
	require.Equal(t, []byte{0, 0, 0, ATYPDomain, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x1f, 0x90}, datagram.Header())
	require.Equal(t, []byte{0, 0, 0, ATYPDomain, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x1f, 0x90, 1, 2, 3}, datagram.Bytes())

	datagram, err = NewDatagram("127.0.0.1:8080", []byte{1, 2, 3})
	require.NoError(t, err)
	require.Equal(t, Datagram{
		0, 0, AddrSpec{
			IP:       net.IPv4(127, 0, 0, 1),
			Port:     8080,
			AddrType: ATYPIPv4,
		},
		[]byte{1, 2, 3},
	}, datagram)
	require.Equal(t, []byte{0, 0, 0, ATYPIPv4, 127, 0, 0, 1, 0x1f, 0x90}, datagram.Header())
	require.Equal(t, []byte{0, 0, 0, ATYPIPv4, 127, 0, 0, 1, 0x1f, 0x90, 1, 2, 3}, datagram.Bytes())
	datagram, err = NewDatagram("[::1]:8080", []byte{1, 2, 3})
	require.NoError(t, err)
	require.Equal(t, Datagram{
		0, 0, AddrSpec{
			IP:       net.IPv6loopback,
			Port:     8080,
			AddrType: ATYPIPv6,
		},
		[]byte{1, 2, 3},
	}, datagram)
	require.Equal(t, []byte{0, 0, 0, ATYPIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x1f, 0x90}, datagram.Header())
	require.Equal(t, []byte{0, 0, 0, ATYPIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x1f, 0x90, 1, 2, 3}, datagram.Bytes())
}

func TestParseDatagram(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantDa  Datagram
		wantErr bool
	}{
		{
			"IPv4",
			[]byte{0, 0, 0, ATYPIPv4, 127, 0, 0, 1, 0x1f, 0x90, 1, 2, 3},
			Datagram{
				0, 0, AddrSpec{
					IP:       net.IPv4(127, 0, 0, 1),
					Port:     8080,
					AddrType: ATYPIPv4,
				},
				[]byte{1, 2, 3},
			},
			false,
		},
		{
			"IPv6",
			[]byte{0, 0, 0, ATYPIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x1f, 0x90, 1, 2, 3},
			Datagram{
				0, 0, AddrSpec{
					IP:       net.IPv6loopback,
					Port:     8080,
					AddrType: ATYPIPv6,
				},
				[]byte{1, 2, 3},
			},
			false,
		},
		{
			"FQDN",
			[]byte{0, 0, 0, ATYPDomain, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x1f, 0x90, 1, 2, 3},
			Datagram{
				0, 0, AddrSpec{
					FQDN:     "localhost",
					Port:     8080,
					AddrType: ATYPDomain,
				},
				[]byte{1, 2, 3},
			},
			false,
		},
		{
			"invalid address type",
			[]byte{0, 0, 0, 0x02, 127, 0, 0, 1, 0x1f, 0x90},
			Datagram{},
			true,
		},
		{
			"less min length",
			[]byte{0, 0, 0, ATYPIPv4, 127, 0, 0, 1, 0x1f},
			Datagram{},
			true,
		},
		{
			"less domain length",
			[]byte{0, 0, 0, ATYPDomain, 10, 127, 0, 0, 1, 0x1f, 0x09},
			Datagram{},
			true,
		},
		{
			"less ipv6 length",
			[]byte{0, 0, 0, ATYPIPv6, 127, 0, 0, 1, 0x1f, 0x09},
			Datagram{},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDa, err := ParseDatagram(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDatagram() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && !reflect.DeepEqual(gotDa, tt.wantDa) {
				t.Errorf("ParseDatagram() gotDa = %v, want %v", gotDa, tt.wantDa)
			}
		})
	}
}

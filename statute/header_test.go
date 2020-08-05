package statute

import (
	"bytes"
	"io"
	"net"
	"reflect"
	"testing"
)

func TestParseHeader(t *testing.T) {
	type args struct {
		r io.Reader
	}
	tests := []struct {
		name    string
		args    args
		wantHd  Header
		wantErr bool
	}{
		{
			"SOCKS5 IPV4",
			args{bytes.NewReader([]byte{VersionSocks5, CommandConnect, 0, ATYPIPv4, 127, 0, 0, 1, 0x1f, 0x90})},
			Header{
				VersionSocks5, CommandConnect, 0,
				AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: 8080},
				ATYPIPv4,
			},
			false,
		},
		{
			"SOCKS5 IPV6",
			args{bytes.NewReader([]byte{VersionSocks5, CommandConnect, 0, ATYPIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1f, 0x90})},
			Header{
				VersionSocks5, CommandConnect, 0,
				AddrSpec{IP: net.IPv6zero, Port: 8080},
				ATYPIPv6,
			},
			false,
		},
		{
			"SOCKS5 FQDN",
			args{bytes.NewReader([]byte{VersionSocks5, CommandConnect, 0, ATYPDomain, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x1f, 0x90})},
			Header{
				VersionSocks5, CommandConnect, 0,
				AddrSpec{FQDN: "localhost", Port: 8080},
				ATYPDomain,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHd, err := ParseHeader(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(gotHd, tt.wantHd) {
				t.Errorf("ParseHeader() gotHd = %+v, want %+v", gotHd, tt.wantHd)
			}
		})
	}
}

func TestHeader_Bytes(t *testing.T) {
	tests := []struct {
		name   string
		header Header
		wantB  []byte
	}{
		{
			"SOCKS5 IPV4",
			Header{
				VersionSocks5, CommandConnect, 0,
				AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: 8080},
				ATYPIPv4,
			},
			[]byte{VersionSocks5, CommandConnect, 0, ATYPIPv4, 127, 0, 0, 1, 0x1f, 0x90},
		},
		{
			"SOCKS5 IPV6",
			Header{
				VersionSocks5, CommandConnect, 0,
				AddrSpec{IP: net.IPv6zero, Port: 8080},
				ATYPIPv6,
			},
			[]byte{VersionSocks5, CommandConnect, 0, ATYPIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1f, 0x90},
		},
		{
			"SOCKS5 FQDN",
			Header{
				VersionSocks5, CommandConnect, 0,
				AddrSpec{FQDN: "localhost", Port: 8080},
				ATYPDomain,
			},
			[]byte{VersionSocks5, CommandConnect, 0, ATYPDomain, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x1f, 0x90},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotB := tt.header.Bytes(); !reflect.DeepEqual(gotB, tt.wantB) {
				t.Errorf("Bytes() = %v, want %v", gotB, tt.wantB)
			}
		})
	}
}

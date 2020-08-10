package statute

import (
	"bytes"
	"io"
	"net"
	"reflect"
	"testing"
)

func TestParseRequest(t *testing.T) {
	tests := []struct {
		name    string
		reader  io.Reader
		want    Request
		wantErr bool
	}{
		{
			"SOCKS5 IPV4",
			bytes.NewReader([]byte{VersionSocks5, CommandConnect, 0, ATYPIPv4, 127, 0, 0, 1, 0x1f, 0x90}),
			Request{
				VersionSocks5, CommandConnect, 0,
				AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: 8080, AddrType: ATYPIPv4},
			},
			false,
		},
		{
			"SOCKS5 IPV6",
			bytes.NewReader([]byte{VersionSocks5, CommandConnect, 0, ATYPIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1f, 0x90}),
			Request{
				VersionSocks5, CommandConnect, 0,
				AddrSpec{IP: net.IPv6zero, Port: 8080, AddrType: ATYPIPv6},
			},
			false,
		},
		{
			"SOCKS5 FQDN",
			bytes.NewReader([]byte{VersionSocks5, CommandConnect, 0, ATYPDomain, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x1f, 0x90}),
			Request{
				VersionSocks5, CommandConnect, 0,
				AddrSpec{FQDN: "localhost", Port: 8080, AddrType: ATYPDomain},
			},
			false,
		},
		{
			"SOCKS5 invalid address type",
			bytes.NewReader([]byte{VersionSocks5, CommandConnect, 0, 0x02, 0, 0, 0, 0, 0, 0}),
			Request{
				Version: VersionSocks5,
				Command: CommandConnect,
				DstAddr: AddrSpec{
					AddrType: 0x02,
				},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHd, err := ParseRequest(tt.reader)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(gotHd, tt.want) {
				t.Errorf("ParseRequest() gotHd = %+v, want %+v", gotHd, tt.want)
			}
		})
	}
}

func TestRequest_Bytes(t *testing.T) {
	tests := []struct {
		name    string
		request Request
		wantB   []byte
	}{
		{
			"SOCKS5 IPV4",
			Request{
				VersionSocks5, CommandConnect, 0,
				AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: 8080, AddrType: ATYPIPv4},
			},
			[]byte{VersionSocks5, CommandConnect, 0, ATYPIPv4, 127, 0, 0, 1, 0x1f, 0x90},
		},
		{
			"SOCKS5 IPV6",
			Request{
				VersionSocks5, CommandConnect, 0,
				AddrSpec{IP: net.IPv6zero, Port: 8080, AddrType: ATYPIPv6},
			},
			[]byte{VersionSocks5, CommandConnect, 0, ATYPIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1f, 0x90},
		},
		{
			"SOCKS5 FQDN",
			Request{
				VersionSocks5, CommandConnect, 0,
				AddrSpec{FQDN: "localhost", Port: 8080, AddrType: ATYPDomain},
			},
			[]byte{VersionSocks5, CommandConnect, 0, ATYPDomain, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x1f, 0x90},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotB := tt.request.Bytes(); !reflect.DeepEqual(gotB, tt.wantB) {
				t.Errorf("Bytes() = %v, want %v", gotB, tt.wantB)
			}
		})
	}
}

func TestParseReply(t *testing.T) {
	tests := []struct {
		name    string
		reader  io.Reader
		want    Reply
		wantErr bool
	}{
		{
			"SOCKS5 IPV4",
			bytes.NewReader([]byte{VersionSocks5, RepSuccess, 0, ATYPIPv4, 127, 0, 0, 1, 0x1f, 0x90}),
			Reply{
				VersionSocks5, RepSuccess, 0,
				AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: 8080, AddrType: ATYPIPv4},
			},
			false,
		},
		{
			"SOCKS5 IPV6",
			bytes.NewReader([]byte{VersionSocks5, RepSuccess, 0, ATYPIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1f, 0x90}),
			Reply{
				VersionSocks5, RepSuccess, 0,
				AddrSpec{IP: net.IPv6zero, Port: 8080, AddrType: ATYPIPv6},
			},
			false,
		},
		{
			"SOCKS5 FQDN",
			bytes.NewReader([]byte{VersionSocks5, RepSuccess, 0, ATYPDomain, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x1f, 0x90}),
			Reply{
				VersionSocks5, RepSuccess, 0,
				AddrSpec{FQDN: "localhost", Port: 8080, AddrType: ATYPDomain},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseReply(tt.reader)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseReply() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseReply() got = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestReply_Bytes(t *testing.T) {
	tests := []struct {
		name  string
		reply Reply
		wantB []byte
	}{
		{
			"SOCKS5 IPV4",
			Reply{
				VersionSocks5, CommandConnect, 0,
				AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: 8080, AddrType: ATYPIPv4},
			},
			[]byte{VersionSocks5, CommandConnect, 0, ATYPIPv4, 127, 0, 0, 1, 0x1f, 0x90},
		},
		{
			"SOCKS5 IPV6",
			Reply{
				VersionSocks5, CommandConnect, 0,
				AddrSpec{IP: net.IPv6zero, Port: 8080, AddrType: ATYPIPv6},
			},
			[]byte{VersionSocks5, CommandConnect, 0, ATYPIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1f, 0x90},
		},
		{
			"SOCKS5 FQDN",
			Reply{
				VersionSocks5, CommandConnect, 0,
				AddrSpec{FQDN: "localhost", Port: 8080, AddrType: ATYPDomain},
			},
			[]byte{VersionSocks5, CommandConnect, 0, ATYPDomain, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x1f, 0x90},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotB := tt.reply.Bytes(); !reflect.DeepEqual(gotB, tt.wantB) {
				t.Errorf("Bytes() = %v, want %v", gotB, tt.wantB)
			}
		})
	}
}

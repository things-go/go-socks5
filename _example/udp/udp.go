package main

import (
	"bytes"
	"log"
	"net"
)

func main() {
	lAddr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 12398,
	}
	l, err := net.ListenUDP("udp4", lAddr)
	if err != nil {
		panic(err)
	}
	defer l.Close()
	go func() {
		for {
			buf := make([]byte, 2048)
			n, remote, err := l.ReadFrom(buf)
			if err != nil {
				return
			}

			if !bytes.Equal(buf[:n], []byte("ping")) {
				log.Println("bad: %v", buf)
			}
			l.WriteTo([]byte("pong"), remote)
		}
	}()

	cli, err := net.DialUDP("udp", nil, lAddr)
	if err != nil {
		panic(err)
	}
	n, err := cli.Write([]byte("ping"))
	if err != nil {
		panic(err)
	}
	rsp := make([]byte, 1024)
	n, _, err = cli.ReadFrom(rsp)
	if err != nil {
		panic(err)
	}
	log.Printf("%s", string(rsp[:n]))
}

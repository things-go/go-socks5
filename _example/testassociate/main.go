package main

import (
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/thinkgos/go-socks5"
	"github.com/thinkgos/go-socks5/ccsocks5"
)

func handleErr(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	locIP := net.ParseIP("127.0.0.1")
	// Create a local listener
	lAddr := &net.UDPAddr{IP: locIP, Port: 12398}
	l, err := net.ListenUDP("udp", lAddr)
	handleErr(err)
	defer l.Close()

	go func() {
		buf := make([]byte, 2048)
		for {
			n, remote, err := l.ReadFrom(buf)
			if err != nil {
				log.Printf("server: %v", err)
				return
			}
			log.Printf("server: %+v", string(buf[:n]))

			l.WriteTo([]byte("pong"), remote) // nolint: errcheck
		}
	}()

	go func() {
		time.Sleep(time.Second)
		c := ccsocks5.NewClient("127.0.0.1:10809")
		handleErr(err)
		con, err := c.Dial("udp", lAddr.String())
		handleErr(err)
		for {
			con.Write([]byte("ping")) // nolint: errcheck
			out := make([]byte, 4)
			con.SetDeadline(time.Now().Add(time.Second)) // nolint: errcheck
			_, err = io.ReadFull(con, out)
			con.SetDeadline(time.Time{}) // nolint: errcheck
			if err != nil {
				log.Printf("client: %v", err)
			} else {
				log.Printf("client: %+v", string(out))
			}
			time.Sleep(time.Second * 2)
		}
	}()

	// Create a SOCKS5 server
	server := socks5.NewServer(socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))))

	// Create SOCKS5 proxy on localhost port 8000
	if err := server.ListenAndServe("tcp", "127.0.0.1:10809"); err != nil {
		panic(err)
	}
}

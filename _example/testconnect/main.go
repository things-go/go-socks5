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
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	handleErr(err)

	go func() {
		conn, err := l.Accept()
		handleErr(err)
		defer conn.Close()
		for {
			buf := make([]byte, 4)
			_, err = io.ReadAtLeast(conn, buf, 4)
			handleErr(err)
			log.Printf("server: %+v", string(buf))
			conn.Write([]byte("pong")) // nolint: errcheck
		}

	}()
	lAddr := l.Addr().(*net.TCPAddr)

	go func() {
		time.Sleep(time.Second * 1)
		client := ccsocks5.NewClient("127.0.0.1:10808")
		con, err := client.Dial("tcp", lAddr.String())
		handleErr(err)

		for {
			con.Write([]byte("ping")) // nolint: errcheck
			out := make([]byte, 4)
			con.SetDeadline(time.Now().Add(time.Second)) // nolint: errcheck
			_, err = io.ReadFull(con, out)
			con.SetDeadline(time.Time{}) // nolint: errcheck
			if err != nil {
				log.Printf("client: %+v", err)
			} else {
				log.Printf("client: %+v", string(out))
			}
			time.Sleep(time.Second * 2)
		}

	}()

	// Create a SOCKS5 server
	server := socks5.NewServer(socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))))

	// Create SOCKS5 proxy on localhost port 8000
	if err := server.ListenAndServe("tcp", "127.0.0.1:10808"); err != nil {
		panic(err)
	}
}

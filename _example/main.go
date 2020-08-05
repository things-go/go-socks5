package main

import (
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/thinkgos/go-socks5"
	"github.com/thinkgos/go-socks5/client"
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

		buf := make([]byte, 4)
		_, err = io.ReadAtLeast(conn, buf, 4)
		handleErr(err)
		log.Printf("server: %+v", string(buf))
		conn.Write([]byte("pong"))
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	go func() {
		time.Sleep(time.Second)
		c, err := client.NewClient("127.0.0.1:1080")
		handleErr(err)
		con, err := c.Dial("tcp", lAddr.String())
		handleErr(err)
		con.Write([]byte("ping"))
		out := make([]byte, 4)
		_ = con.SetDeadline(time.Now().Add(time.Second)) // nolint: errcheck
		_, err = io.ReadFull(con, out)
		log.Printf("client: %+v", string(out))
	}()

	// Create a SOCKS5 server
	server := socks5.NewServer(socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))))

	// Create SOCKS5 proxy on localhost port 8000
	if err := server.ListenAndServe("tcp", "127.0.0.1:1080"); err != nil {
		panic(err)
	}
}

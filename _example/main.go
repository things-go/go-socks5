package main

import (
	"log"
	"os"

	"github.com/thinkgos/go-socks5"
)

func main() {
	// Create a SOCKS5 server
	server := socks5.New(socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))))

	// Create SOCKS5 proxy on localhost port 8000
	if err := server.ListenAndServe("tcp", "127.0.0.1:1080"); err != nil {
		panic(err)
	}
}

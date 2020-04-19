package main

import (
	"log"
	"os"

	"github.com/thinkgos/socks5"
)

func main() {
	// Create a SOCKS5 server
	conf := &socks5.Config{
		Logger: socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags)),
	}
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	// Create SOCKS5 proxy on localhost port 8000
	if err := server.ListenAndServe("tcp", "127.0.0.1:1080"); err != nil {
		panic(err)
	}
}

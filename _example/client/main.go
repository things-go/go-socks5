package main

import (
	"time"

	"github.com/thinkgos/go-socks5/ccsocks5"
)

func main() {
	client := ccsocks5.NewClient("127.0.0.1:10800")
	conn, err := client.Dial("tcp", "127.0.0.1:12345") // server you want to visitor
	if err != nil {
		panic(err)
	}
	conn.Write([]byte("hahaha"))
	time.Sleep(time.Second)
}

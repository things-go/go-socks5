go-socks5 
=========

[![Build Status](https://travis-ci.org/thinkgos/go-socks5.svg?branch=master)](https://travis-ci.org/thinkgos/go-socks5)
[![codecov](https://codecov.io/gh/thinkgos/go-socks5/branch/master/graph/badge.svg)](https://codecov.io/gh/thinkgos/go-socks5)
![Action Status](https://github.com/thinkgos/go-socks5/workflows/Go/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/thinkgos/go-socks5)](https://goreportcard.com/report/github.com/thinkgos/go-socks5)
[![License](https://img.shields.io/github/license/thinkgos/go-socks5)](https://github.com/thinkgos/go-socks5/raw/master/LICENSE)

Provides the `socks5` package that implements a [SOCKS5 server](http://en.wikipedia.org/wiki/SOCKS).
SOCKS (Secure Sockets) is used to route traffic between a client and server through
an intermediate proxy layer. This can be used to bypass firewalls or NATs.

Feature
=======

The package has the following features:
* "No Auth" mode
* User/Password authentication optional user addr limit
* Support for the CONNECT command
* Support for the ASSOCIATE command
* Rules to do granular filtering of commands
* Custom DNS resolution
* Unit tests
* Custom goroutine pool
* Custom logger
* buffer pool design

TODO
====

The package still needs the following:
* Support for the BIND command

Example
=======

Below is a simple example of usage

```go
// Create a SOCKS5 server
server := socks5.NewServer()

// Create SOCKS5 proxy on localhost port 8000
if err := server.ListenAndServe("tcp", "127.0.0.1:8000"); err != nil {
  panic(err)
}
```

# Reference
- [rfc1928](https://www.ietf.org/rfc/rfc1928.txt) 
- original armon go-sock5 [go-sock5](https://github.com/armon/go-socks5)  
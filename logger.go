package socks5

import (
	"log"
)

type Logger interface {
	Errorf(format string, arg ...interface{})
}

// 标准输出
type Std struct {
	*log.Logger
}

func NewLogger(l *log.Logger) *Std {
	return &Std{l}
}

func (sf Std) Errorf(format string, args ...interface{}) {
	sf.Logger.Printf("[E]: "+format, args...)
}

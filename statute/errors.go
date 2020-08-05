package statute

import (
	"errors"
)

var (
	ErrUnrecognizedAddrType = errors.New("Unrecognized address type")
	ErrNotSupportVersion    = errors.New("not support version")
)

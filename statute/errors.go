package statute

import (
	"errors"
)

// error defined
var (
	ErrUnrecognizedAddrType = errors.New("Unrecognized address type")
	ErrNotSupportVersion    = errors.New("not support version")
	ErrNotSupportMethod     = errors.New("not support method")
)

package statute

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMethodRequest(t *testing.T) {
	mr := NewMethodRequest(VersionSocks5, []byte{MethodNoAuth, MethodUserPassAuth})
	want := []byte{VersionSocks5, 2, MethodNoAuth, MethodUserPassAuth}
	assert.Equal(t, want, mr.Bytes())

	mr1, err := ParseMethodRequest(bytes.NewReader(want))
	require.NoError(t, err)
	assert.Equal(t, mr, mr1)
}

func TestMethodReply(t *testing.T) {
	mr, err := ParseMethodReply(bytes.NewReader([]byte{VersionSocks5, RepSuccess}))
	require.NoError(t, err)
	assert.Equal(t, MethodReply{VersionSocks5, RepSuccess}, mr)
}

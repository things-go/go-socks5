package statute

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserPassRequest(t *testing.T) {
	want := []byte{UserPassAuthVersion, 4, 'u', 's', 'e', 'r', 8, 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}

	userpass := NewUserPassRequest(UserPassAuthVersion, []byte("user"), []byte("password"))
	assert.Equal(t, want, userpass.Bytes())

	upr, err := ParseUserPassRequest(bytes.NewReader(want))
	require.NoError(t, err)
	assert.Equal(t, userpass, upr)
}

func TestUserPassReply(t *testing.T) {
	reader := bytes.NewReader([]byte{UserPassAuthVersion, AuthSuccess})

	upr, err := ParseUserPassReply(reader)
	require.NoError(t, err)
	assert.Equal(t, UserPassReply{UserPassAuthVersion, AuthSuccess}, upr)
}

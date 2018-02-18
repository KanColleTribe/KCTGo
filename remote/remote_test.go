package remote

import (
	"testing"
)

func Test_Remote(t *testing.T) {
	server := NewRemoteServer("127.0.0.1", "18999")
	server.Run()
}

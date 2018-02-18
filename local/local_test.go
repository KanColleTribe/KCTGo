package local

import (
	"testing"
)

func Test_Local(t *testing.T) {
	server := NewLocalServer("127.0.0.1", "18996", "tcp",
		"127.0.0.1", "18999")
	server.Run()
}

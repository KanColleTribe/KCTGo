package remote

import (
	"../lib/log"
	"os"
	"testing"
)

func Test_Remote(t *testing.T) {
	logger := log.NewLogger(os.Stdout, os.Stdout)
	server := NewRemoteServer("127.0.0.1", "18999", "tcp", "", logger)
	server.Run()
}

package local

import (
	"../lib/log"
	"os"
	"testing"
)

func Test_Local(t *testing.T) {
	logger := log.NewLogger(os.Stdout, os.Stdout)
	server := NewLocalServer("127.0.0.1", "18996", "tcp",
		"127.0.0.1", "18999", logger)
	server.Run()
}

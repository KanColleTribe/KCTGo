package local

import (
	"os"
	"testing"

	"github.com/wuyuMk7/KCTGo/lib/log"
)

func Test_Local(t *testing.T) {
	logger := log.NewLogger(os.Stdout, os.Stdout)
	server := NewLocalServer("127.0.0.1", "18996", "tcp",
		"127.0.0.1", "18999", logger,
		"testuser", "test123", "sharing", "aes", "pk.key")
	server.Run()
}

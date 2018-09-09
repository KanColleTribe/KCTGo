package remote

import (
	"github.com/wuyuMk7/KCTGo/lib/log"
	"os"
	"testing"
)

func Test_Remote(t *testing.T) {
	logger := log.NewLogger(os.Stdout, os.Stdout)
	server := NewRemoteServer("127.0.0.1", "18999", "tcp", logger, "sk.key")
	server.Run()
}

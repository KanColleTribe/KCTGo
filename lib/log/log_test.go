package log

import (
	"os"
	"testing"
)

func Test_Log(t *testing.T) {
	info, err := os.OpenFile("kctgo_info.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}

	error, err := os.OpenFile("kctgo_error.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}

	logger := NewLogger(info, error)
	logger.Info("First attempt.")
	logger.Error("Test error log")

	logger.info.SetPrefix("[INFO_PRE]")
	logger.Info("Test prefix")
	logger.error.SetPrefix("[ERROR_PRE]")
	logger.Error("Test prefix")
}

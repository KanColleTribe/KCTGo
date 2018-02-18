package lib

import (
	"io"
	"log"
)

type Logger struct {
	info  *log.Logger
	error *log.Logger
}

func NewLogger(info io.Writer, error io.Writer) *Logger {
	logger := &Logger{}
	logger.info = log.New(info, "[INFO]", log.LstdFlags|log.LUTC)
	logger.error = log.New(error, "[ERROR]", log.LstdFlags|log.LUTC)

	return logger
}

func (log *Logger) Info(msg string) {
	log.info.Println(msg)
}

func (log *Logger) Error(msg string) {
	log.error.Println(msg)
}

func (log *Logger) Fatal(msg string) {
	log.error.Fatal(msg)
}

package log

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

func (log *Logger) Info(msg ...interface{}) {
	log.info.Println(msg)
}

func (log *Logger) Error(msg ...interface{}) {
	log.error.Println(msg)
}

func (log *Logger) Fatal(msg ...interface{}) {
	log.error.Fatal(msg)
}

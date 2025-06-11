package commons

import (
	"os"
	"strings"

	"github.com/labstack/gommon/log"
)

var Logger = newLogger()

func newLogger() *log.Logger {
	logger := log.New("qdroid")
	level := strings.ToUpper(os.Getenv("LOG_LEVEL"))
	switch level {
	case "DEBUG":
		logger.SetLevel(log.DEBUG)
	case "INFO":
		logger.SetLevel(log.INFO)
	case "WARN":
		logger.SetLevel(log.WARN)
	case "ERROR":
		logger.SetLevel(log.ERROR)
	case "OFF":
		logger.SetLevel(log.OFF)
	default:
		logger.SetLevel(log.INFO)
	}
	logger.SetHeader("${time_rfc3339} ${level} ${short_file}:${line} -")
	return logger
}

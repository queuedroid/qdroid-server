// SPDX-License-Identifier: GPL-3.0-only

package commons

import (
	"os"
	"slices"
	"strings"

	"github.com/labstack/gommon/log"
)

var Logger = log.New("qdroid")

func InitLogger() {
	logger := log.New("qdroid")
	level := strings.ToUpper(os.Getenv("LOG_LEVEL"))
	debug := slices.Contains(os.Args[1:], "--debug")
	if debug {
		level = "DEBUG"
	}
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
	Logger = logger
}

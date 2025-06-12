// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"os"
	"qdroid-server/commons"
	"qdroid-server/db"
	"qdroid-server/routes"
	"slices"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
)

func main() {
	commons.LoadEnvFile()
	commons.InitLogger()

	e := echo.New()
	e.HideBanner = true

	e.Logger.SetLevel(commons.Logger.Level())
	e.Logger.SetHeader("${time_rfc3339} ${level} ${short_file}:${line} -")

	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogURI:      true,
		LogStatus:   true,
		LogMethod:   true,
		LogLatency:  true,
		LogRemoteIP: true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			logMsg := func(format string, args ...any) {
				switch {
				case v.Status >= 500:
					e.Logger.Errorf(format, args...)
				case v.Status >= 400:
					e.Logger.Warnf(format, args...)
				default:
					e.Logger.Infof(format, args...)
				}
			}
			logMsg("%s %s - %d - %.2fms - %s",
				v.Method,
				v.URI,
				v.Status,
				float64(v.Latency.Microseconds())/1000.0,
				v.RemoteIP,
			)
			return nil
		},
	}))
	debugMode := slices.Contains(os.Args[1:], "--debug")
	if debugMode {
		e.Logger.Warn("Debug mode is enabled.")
		e.Debug = true
		e.Logger.SetLevel(log.DEBUG)
	}

	e.Use(middleware.Recover())

	db.InitDB()
	if slices.Contains(os.Args[1:], "--migrate-db") {
		commons.Logger.Debug("--migrate-db flag detected, running migrations")
		db.MigrateDB()
	}

	routes.RegisterRoutes(e)

	port := commons.GetEnv("PORT")
	if port == "" {
		port = ":8080"
	}
	if port[0] != ':' {
		port = ":" + port
	}
	e.Logger.Fatal(e.Start(port))
}

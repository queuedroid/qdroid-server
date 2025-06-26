// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"net/http"
	"os"
	"qdroid-server/commons"
	"qdroid-server/db"
	"qdroid-server/docs"
	"qdroid-server/routes"
	"slices"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	echoSwagger "github.com/swaggo/echo-swagger"
)

func main() {
	time.Local = time.UTC

	commons.LoadEnvFile()
	commons.InitLogger()

	e := echo.New()
	e.HideBanner = true

	docs.SwaggerInfo.Title = "QueueDroid API"
	docs.SwaggerInfo.Description = "QueueDroid API documentation."
	e.GET("/docs/*", echoSwagger.WrapHandler)

	e.Logger.SetLevel(commons.Logger.Level())
	e.Logger.SetHeader("${time_rfc3339} ${level} ${short_file}:${line} -")

	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			err := next(c)
			if err != nil {
				if he, ok := err.(*echo.HTTPError); ok && he.Code == http.StatusInternalServerError {
					msg := "Something went wrong. We're working to fix it as quickly as possible. Please try again later. If the issue persists, please contact support."
					if !c.Response().Committed {
						return c.JSON(http.StatusInternalServerError, map[string]string{"message": msg})
					}
					return nil
				}
			}
			return err
		}
	})

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

	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		Skipper: func(c echo.Context) bool {
			return debugMode
		},
	}))
	corsOrigins := commons.GetEnv("CORS_ORIGINS")
	var allowedOrigins []string
	if corsOrigins != "" {
		importedOrigins := strings.Split(corsOrigins, ",")
		for _, o := range importedOrigins {
			trimmed := strings.TrimSpace(o)
			if trimmed != "" {
				allowedOrigins = append(allowedOrigins, trimmed)
			}
		}
	} else {
		allowedOrigins = []string{"*"}
	}

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: allowedOrigins,
		Skipper: func(c echo.Context) bool {
			return debugMode
		},
	}))

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

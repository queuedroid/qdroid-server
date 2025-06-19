// SPDX-License-Identifier: GPL-3.0-only

package routes

import (
	"qdroid-server/commons"
	"qdroid-server/handlers"

	"github.com/labstack/echo/v4"
)

func RegisterRoutes(e *echo.Echo) {
	commons.Logger.Debug("Registering v1 routes")
	api_v1 := e.Group("/v1")
	api_v1.POST("/auth/signup", handlers.SignupHandler)
	api_v1.POST("/auth/login", handlers.LoginHandler)
	commons.Logger.Info("v1 routes registered successfully")
}

package routes

import (
	"qdroid-server/handlers"

	"github.com/labstack/echo/v4"
)

func RegisterRoutes(e *echo.Echo) {
	api := e.Group("/v1")
	api.POST("/signup", handlers.SignupHandler)
	api.POST("/login", handlers.LoginHandler)
}

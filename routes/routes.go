// SPDX-License-Identifier: GPL-3.0-only

package routes

import (
	"qdroid-server/commons"
	"qdroid-server/handlers"
	"qdroid-server/middlewares"

	"github.com/labstack/echo/v4"
)

func RegisterRoutes(e *echo.Echo) {
	commons.Logger.Debug("Registering v1 routes")
	api_v1 := e.Group("/v1")
	api_v1.POST("/auth/signup", handlers.SignupHandler)
	api_v1.POST("/auth/login", handlers.LoginHandler)
	api_v1.POST("/auth/logout", handlers.LogoutHandler, middlewares.VerifySessionMiddleware)
	api_v1.GET("/exchanges/", handlers.GetAllExchangesHandler, middlewares.VerifySessionMiddleware)
	api_v1.POST("/exchanges/", handlers.CreateExchangeHandler, middlewares.VerifySessionMiddleware)
	api_v1.GET("/exchanges/:exchange_id", handlers.GetExchangeHandler, middlewares.VerifySessionMiddleware)
	api_v1.PUT("/exchanges/:exchange_id", handlers.UpdateExchangeHandler, middlewares.VerifySessionMiddleware)
	api_v1.DELETE("/exchanges/:exchange_id", handlers.DeleteExchangeHandler, middlewares.VerifySessionMiddleware)
	api_v1.POST("/exchanges/:exchange_id/queues", handlers.CreateAndBindQueueHandler, middlewares.VerifySessionMiddleware)
	api_v1.GET("/users/", handlers.GetUserHandler, middlewares.VerifySessionMiddleware)
	api_v1.POST("/messages/send", handlers.SendMessageHandler, middlewares.VerifySessionMiddleware)
	commons.Logger.Info("v1 routes registered successfully")
}

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
	api_v1.POST("/auth/logout", handlers.LogoutHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession))
	api_v1.POST("/auth/api-keys", handlers.CreateAPIKeyHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession))
	api_v1.GET("/auth/api-keys", handlers.GetAllAPIKeyHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession))
	api_v1.DELETE("/auth/api-keys/:key_id", handlers.DeleteAPIKeyHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession))
	api_v1.GET("/exchanges/", handlers.GetAllExchangesHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession, middlewares.AuthMethodAPIKey))
	api_v1.POST("/exchanges/", handlers.CreateExchangeHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession, middlewares.AuthMethodAPIKey))
	api_v1.GET("/exchanges/:exchange_id", handlers.GetExchangeHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession, middlewares.AuthMethodAPIKey))
	api_v1.PUT("/exchanges/:exchange_id", handlers.UpdateExchangeHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession, middlewares.AuthMethodAPIKey))
	api_v1.DELETE("/exchanges/:exchange_id", handlers.DeleteExchangeHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession, middlewares.AuthMethodAPIKey))
	api_v1.GET("/exchanges/:exchange_id/connection", handlers.GetExchangeConnectionHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession, middlewares.AuthMethodAPIKey))
	api_v1.GET("/exchanges/:exchange_id/queues/:queue_id/connection", handlers.GetQueueConnectionHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession, middlewares.AuthMethodAPIKey))
	api_v1.DELETE("/exchanges/:exchange_id/queues/:queue_id/purge", handlers.PurgeQueueHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession, middlewares.AuthMethodAPIKey))
	api_v1.DELETE("/exchanges/:exchange_id/queues/:queue_id", handlers.DeleteQueueHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession, middlewares.AuthMethodAPIKey))
	api_v1.POST("/exchanges/:exchange_id/queues", handlers.CreateAndBindQueueHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession, middlewares.AuthMethodAPIKey))
	api_v1.GET("/exchanges/:exchange_id/queues", handlers.GetExchangeQueuesHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession, middlewares.AuthMethodAPIKey))
	api_v1.GET("/users/", handlers.GetUserHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession))
	api_v1.DELETE("/users/", handlers.DeleteAccountHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession))
	api_v1.PUT("/users/password", handlers.ChangePasswordHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession))
	api_v1.POST("/messages/send", handlers.SendMessageHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession, middlewares.AuthMethodAPIKey))
	api_v1.POST("/messages/bulk-send", handlers.SendBulkMessagesHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession, middlewares.AuthMethodAPIKey))
	api_v1.GET("/event-logs", handlers.GetEventLogsHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession, middlewares.AuthMethodAPIKey))
	api_v1.GET("/event-logs/summary", handlers.GetEventLogsSummaryHandler, middlewares.VerifyAuthMiddleware(middlewares.AuthMethodSession, middlewares.AuthMethodAPIKey))
	commons.Logger.Info("v1 routes registered successfully")
}

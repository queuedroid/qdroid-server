// SPX-License-Identifier: GPL-3.0-only

package handlers

import (
	"net/http"
	"qdroid-server/crypto"
	"qdroid-server/db"
	"qdroid-server/models"
	"qdroid-server/rabbitmq"

	"github.com/labstack/echo/v4"
)

func CreateExchangeHandler(c echo.Context) error {
	logger := c.Logger()

	rmqClient, err := rabbitmq.NewClient(rabbitmq.RabbitMQConfig{})
	if err != nil {
		logger.Error("Failed to initialize RabbitMQ client:", err)
		return echo.ErrInternalServerError
	}

	session, ok := c.Get("session").(models.Session)
	if !ok {
		logger.Error("Session not found in context.")
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired session token, please login again",
		}
	}

	var req CreateExchangeRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Invalid create exchange request payload:", err)
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Invalid request payload, please ensure it is well-formed and has content-type application/json header",
		}
	}

	if req.Label == "" {
		logger.Error("Label is required.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "label field is required",
		}
	}

	count := db.Conn.Where("label = ? AND user_id = ?", req.Label, session.UserID).First(&models.Exchange{}).RowsAffected
	if count > 0 {
		logger.Errorf("Duplicate exchange label detected.")
		return &echo.HTTPError{
			Code:    http.StatusConflict,
			Message: "You already have an exchange with this label. Please try another one.",
		}
	}

	exchangeID, err := crypto.GenerateRandomString("exch_", 16, "hex")
	if err != nil {
		logger.Errorf("Failed to generate exchange ID: %v", err)
		return echo.ErrInternalServerError
	}

	user := models.User{}
	if err := db.Conn.Where("id = ?", session.UserID).First(&user).Error; err != nil {
		logger.Errorf("Failed to find user: %v", err)
		return echo.ErrInternalServerError
	}

	exchange := models.Exchange{
		ExchangeID:  exchangeID,
		Label:       req.Label,
		Description: req.Description,
		UserID:      user.ID,
	}

	tx := db.Conn.Begin()
	if tx.Error != nil {
		logger.Errorf("Transaction begin failed: %v", tx.Error)
		return echo.ErrInternalServerError
	}

	if err := tx.Create(&exchange).Error; err != nil {
		tx.Rollback()
		logger.Errorf("Failed to create exchange: %v", err)
		return echo.ErrInternalServerError
	}

	if err := rmqClient.CreateExchange(user.AccountID, exchangeID, "topic", true); err != nil {
		tx.Rollback()
		logger.Errorf("Failed to create exchange in RabbitMQ: %v", err)
		return echo.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		logger.Errorf("Transaction commit failed: %v", err)
		return echo.ErrInternalServerError
	}

	logger.Infof("Exchange created successfully.")
	return c.JSON(http.StatusCreated, CreateExchangeResponse{
		Message:     "Successfully created exchange",
		ExchangeID:  exchange.ExchangeID,
		Label:       exchange.Label,
		Description: exchange.Description,
		CreatedAt:   exchange.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:   exchange.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	})
}

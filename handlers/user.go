// SPDX-License-Identifier: GPL-3.0-only

package handlers

import (
	"fmt"
	"net/http"
	"qdroid-server/crypto"
	"qdroid-server/db"
	"qdroid-server/models"
	"qdroid-server/passwordcheck"
	"qdroid-server/rabbitmq"

	"github.com/labstack/echo/v4"
)

func SignupHandler(c echo.Context) error {
	logger := c.Logger()

	rmqClient, err := rabbitmq.NewClient(rabbitmq.RabbitMQConfig{})
	if err != nil {
		logger.Error("Failed to initialize RabbitMQ client:", err)
		return echo.ErrInternalServerError
	}

	var req SignupRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Invalid signup request payload:", err)
		return echo.ErrBadRequest
	}

	if req.Email == "" {
		logger.Error("Email is required.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "email field is required",
		}
	}

	if req.Password == "" {
		logger.Error("Password is required.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "password field is required",
		}
	}

	if err := passwordcheck.ValidatePassword(c.Request().Context(), req.Password); err != nil {
		logger.Error("Password validation failed: ", err)
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: fmt.Sprintf("Invalid password: %v", err.Error()),
		}
	}

	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		logger.Errorf("Failed to hash password: %v", err)
		return echo.ErrInternalServerError
	}

	user := models.User{
		Email:       req.Email,
		Password:    hash,
		PhoneNumber: &req.PhoneNumber,
	}

	tx := db.DB.Begin()
	if tx.Error != nil {
		logger.Errorf("Transaction begin failed: %v", tx.Error)
		return echo.ErrInternalServerError
	}

	if err := tx.Create(&user).Error; err != nil {
		tx.Rollback()
		logger.Errorf("Failed to create user: %v", err)
		return echo.NewHTTPError(http.StatusConflict, "User already exists")
	}

	if err := rmqClient.CreateVhost(user.Email); err != nil {
		tx.Rollback()
		logger.Errorf("Failed to create RabbitMQ vhost: %v", err)
		return echo.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		logger.Errorf("Transaction commit failed: %v", err)
		return echo.ErrInternalServerError
	}

	logger.Infof("User signed up successfully")
	return c.JSON(http.StatusCreated, map[string]string{"message": "Signup successful"})
}

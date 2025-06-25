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

// SignupHandler godoc
// @Summary      Register a new user
// @Description  Creates a new user account.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        signupRequest  body  SignupRequest  true  "Signup request payload"
// @Success      201 {object} SignupResponse 	 "Signup successful"
// @Failure      400 {object} echo.HTTPError     "Bad request, missing required fields"
// @Failure      409 {object} echo.HTTPError     "Duplicate user"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/auth/signup [post]
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

	count := db.Conn.Where("email = ?", req.Email).First(&models.User{}).RowsAffected
	if count > 0 {
		logger.Errorf("This email is already registered.")
		return &echo.HTTPError{
			Code:    http.StatusConflict,
			Message: "This email is already registered, please try another one.",
		}
	}

	newCrypto := crypto.NewCrypto()
	hash, err := newCrypto.HashPassword(req.Password)
	if err != nil {
		logger.Errorf("Failed to hash password: %v", err)
		return echo.ErrInternalServerError
	}

	aid, err := crypto.GenerateRandomString("acct_", 16, "hex")
	if err != nil {
		logger.Errorf("Failed to generate account ID: %v", err)
		return echo.ErrInternalServerError
	}

	att, err := crypto.GenerateRandomString("", 32, "hex")
	if err != nil {
		logger.Errorf("Failed to generate account token: %v", err)
		return echo.ErrInternalServerError
	}

	user := models.User{
		AccountID:    aid,
		AccountToken: att,
		Email:        req.Email,
		Password:     hash,
		PhoneNumber:  &req.PhoneNumber,
	}

	tx := db.Conn.Begin()
	if tx.Error != nil {
		logger.Errorf("Transaction begin failed: %v", tx.Error)
		return echo.ErrInternalServerError
	}

	if err := tx.Create(&user).Error; err != nil {
		tx.Rollback()
		logger.Errorf("Failed to create user: %v", err)
		return echo.ErrInternalServerError
	}

	if err := rmqClient.CreateVhost(user.AccountID); err != nil {
		tx.Rollback()
		logger.Errorf("Failed to create RabbitMQ vhost: %v", err)
		return echo.ErrInternalServerError
	}

	if err := rmqClient.CreateUser(user.AccountID, user.AccountToken, []string{"management"}); err != nil {
		rmqClient.DeleteVhost(user.AccountID)
		tx.Rollback()
		logger.Errorf("Failed to create RabbitMQ user: %v", err)
		return echo.ErrInternalServerError
	}

	if err := rmqClient.SetPermissions(user.AccountID, user.AccountID, ".*", ".*", ".*"); err != nil {
		rmqClient.DeleteUser(user.AccountID)
		rmqClient.DeleteVhost(user.AccountID)
		tx.Rollback()
		logger.Errorf("Failed to set RabbitMQ permissions: %v", err)
		return echo.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		logger.Errorf("Transaction commit failed: %v", err)
		return echo.ErrInternalServerError
	}

	logger.Infof("User signed up successfully")
	return c.JSON(http.StatusCreated, SignupResponse{Message: "Signup successful"})
}

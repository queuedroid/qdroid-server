// SPDX-License-Identifier: GPL-3.0-only

package handlers

import (
	"net/http"
	"qdroid-server/commons"
	"qdroid-server/crypto"
	"qdroid-server/db"
	"qdroid-server/models"
	"qdroid-server/rabbitmq"

	"github.com/labstack/echo/v4"
)

var (
	rmqURL = func() string {
		url := commons.GetEnv("RABBITMQ_API_URL")
		if url == "" {
			return "http://localhost:15672"
		}
		return url
	}()
	rmqUser = func() string {
		user := commons.GetEnv("RABBITMQ_USERNAME")
		if user == "" {
			return "guest"
		}
		return user
	}()
	rmqPass = func() string {
		pass := commons.GetEnv("RABBITMQ_PASSWORD")
		if pass == "" {
			return "guest"
		}
		return pass
	}()
)

func SignupHandler(c echo.Context) error {
	logger := c.Logger()

	rmqClient, err := rabbitmq.NewClient(rmqURL, rmqUser, rmqPass)
	if err != nil {
		return echo.ErrInternalServerError
	}

	_ = rmqClient

	var req SignupRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Invalid signup request payload:", err)
		return c.String(http.StatusBadRequest, "Invalid request")
	}
	if req.Username == "" || req.Password == "" {
		logger.Error("Username and password required for signup")
		return c.String(http.StatusBadRequest, "Username and password required")
	}
	user := models.User{
		Username: req.Username,
		Password: crypto.HashPassword(req.Password),
	}
	if err := db.DB.Create(&user).Error; err != nil {
		logger.Error("User already exists or DB error:", err)
		return c.String(http.StatusConflict, "User already exists")
	}
	logger.Info("User signed up:", req.Username)
	return c.String(http.StatusCreated, "Signup successful")
}

func LoginHandler(c echo.Context) error {
	logger := c.Logger()
	commons.Logger.Debug("LoginHandler called")
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Invalid login request payload:", err)
		return c.String(http.StatusBadRequest, "Invalid request")
	}
	var user models.User
	if err := db.DB.Where("username = ?", req.Username).First(&user).Error; err != nil {
		logger.Error("Invalid username or DB error during login:", err)
		return c.String(http.StatusUnauthorized, "Invalid username or password")
	}
	if !crypto.VerifyPassword(req.Password, user.Password) {
		logger.Error("Password verification failed for user:", req.Username)
		return c.String(http.StatusUnauthorized, "Invalid username or password")
	}
	logger.Info("User logged in:", req.Username)
	return c.String(http.StatusOK, "Login successful")
}

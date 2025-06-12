// SPDX-License-Identifier: GPL-3.0-only

package handlers

import (
	"net/http"
	"qdroid-server/commons"
	"qdroid-server/crypto"
	"qdroid-server/db"
	"qdroid-server/models"

	"github.com/labstack/echo/v4"
)

type SignupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func SignupHandler(c echo.Context) error {
	logger := c.Logger()
	commons.Logger.Debug("SignupHandler called")
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

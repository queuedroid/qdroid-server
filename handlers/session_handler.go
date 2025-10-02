// SPDX-License-Identifier: GPL-3.0-only

package handlers

import (
	"fmt"
	"net/http"
	"qdroid-server/crypto"
	"qdroid-server/db"
	"qdroid-server/middlewares"
	"qdroid-server/models"
	"time"

	"github.com/labstack/echo/v4"
)

// GetSessionsHandler godoc
// @Summary      Get user sessions
// @Description  Retrieves all active sessions for the authenticated user, including session details like device information, location, and last activity.
// @Tags         sessions
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Param        page     query   int     false  "Page number (default 1)"
// @Param        page_size query  int     false  "Page size (default 10, max 100)"
// @Success      200 {object} SessionListResponse "Paginated list of user sessions"
// @Failure      401 {object} echo.HTTPError     "Unauthorized, invalid or expired session token"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/sessions [get]
func GetSessionsHandler(c echo.Context) error {
	logger := c.Logger()

	user, err := middlewares.GetAuthenticatedUser(c)
	if err != nil {
		logger.Error("Failed to get authenticated user:", err)
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired authentication token, please login again",
		}
	}

	currentSession, currentSessionExists := c.Get("session").(models.Session)

	page := 1
	pageSize := 10
	if p := c.QueryParam("page"); p != "" {
		if _, err := fmt.Sscanf(p, "%d", &page); err != nil || page < 1 {
			page = 1
		}
	}
	if ps := c.QueryParam("page_size"); ps != "" {
		if _, err := fmt.Sscanf(ps, "%d", &pageSize); err != nil || pageSize < 1 {
			pageSize = 10
		}
	}
	if pageSize > 100 {
		pageSize = 100
	}

	var total int64
	if err := db.Conn.Model(&models.Session{}).Where("user_id = ?", user.ID).Count(&total).Error; err != nil {
		logger.Errorf("Failed to count sessions: %v", err)
		return echo.ErrInternalServerError
	}

	offset := (page - 1) * pageSize
	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))

	var sessions []models.Session
	if err := db.Conn.Where("user_id = ?", user.ID).
		Order("last_used_at DESC, created_at DESC").
		Limit(pageSize).
		Offset(offset).
		Find(&sessions).Error; err != nil {
		logger.Errorf("Failed to fetch sessions: %v", err)
		return echo.ErrInternalServerError
	}

	newCrypto := crypto.NewCrypto()

	sessionDetails := make([]SessionDetails, 0, len(sessions))
	for _, session := range sessions {
		detail := SessionDetails{
			ID:        session.ID,
			CreatedAt: session.CreatedAt.Format(time.RFC3339),
			UpdatedAt: session.UpdatedAt.Format(time.RFC3339),
		}

		if currentSessionExists && currentSession.ID == session.ID {
			detail.IsCurrent = true
		}

		if session.ExpiresAt != nil && session.ExpiresAt.Before(time.Now()) {
			detail.IsExpired = true
		}

		if session.LastUsedAt != nil {
			lastUsed := session.LastUsedAt.Format(time.RFC3339)
			detail.LastUsedAt = &lastUsed
		}

		if session.IPAddressEncrypted != nil {
			if decryptedIP, err := newCrypto.DecryptData(*session.IPAddressEncrypted, "AES-GCM"); err == nil {
				ipStr := string(decryptedIP)
				detail.IPAddress = &ipStr
			}
		}

		if session.UserAgentEncrypted != nil {
			if decryptedUA, err := newCrypto.DecryptData(*session.UserAgentEncrypted, "AES-GCM"); err == nil {
				uaStr := string(decryptedUA)
				detail.UserAgent = &uaStr
			}
		}

		sessionDetails = append(sessionDetails, detail)
	}

	pagination := PaginationDetails{
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		TotalPages: totalPages,
	}

	return c.JSON(http.StatusOK, SessionListResponse{
		Data:       sessionDetails,
		Pagination: pagination,
		Message:    "Sessions retrieved successfully",
	})
}

// DeleteSessionHandler godoc
// @Summary      Delete a session
// @Description  Deletes a specific session by ID. This will log out the user from that session. Cannot delete the current session - use logout instead.
// @Tags         sessions
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Param        session_id    path    string  true  "Session ID"
// @Success      200 {object} GenericResponse "Session deleted successfully"
// @Failure      400 {object} echo.HTTPError     "Bad request, cannot delete current session"
// @Failure      401 {object} echo.HTTPError     "Unauthorized, invalid or expired session token"
// @Failure      404 {object} echo.HTTPError     "Session not found"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/sessions/{session_id} [delete]
func DeleteSessionHandler(c echo.Context) error {
	logger := c.Logger()

	user, err := middlewares.GetAuthenticatedUser(c)
	if err != nil {
		logger.Error("Failed to get authenticated user:", err)
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired authentication token, please login again",
		}
	}

	sessionIDStr := c.Param("session_id")
	if sessionIDStr == "" {
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Session ID is required",
		}
	}

	var sessionID uint
	if _, err := fmt.Sscanf(sessionIDStr, "%d", &sessionID); err != nil {
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Invalid session ID format",
		}
	}

	currentSession, currentSessionExists := c.Get("session").(models.Session)
	if currentSessionExists && currentSession.ID == sessionID {
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Cannot delete current session. Use logout endpoint instead.",
		}
	}

	session := models.Session{}
	if err := db.Conn.Where("id = ? AND user_id = ?", sessionID, user.ID).First(&session).Error; err != nil {
		logger.Errorf("Session not found: %v", err)
		return &echo.HTTPError{
			Code:    http.StatusNotFound,
			Message: "Session not found",
		}
	}

	if err := db.Conn.Unscoped().Delete(&session).Error; err != nil {
		logger.Errorf("Failed to delete session: %v", err)
		return echo.ErrInternalServerError
	}

	logger.Infof("Session %d deleted successfully for user %d", sessionID, user.ID)
	return c.JSON(http.StatusOK, GenericResponse{
		Message: "Session deleted successfully",
	})
}

// DeleteAllSessionsHandler godoc
// @Summary      Delete all other sessions
// @Description  Deletes all sessions except the current one. This will log out the user from all other devices/sessions.
// @Tags         sessions
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Success      200 {object} DeleteAllSessionsResponse "All other sessions deleted successfully"
// @Failure      401 {object} echo.HTTPError     "Unauthorized, invalid or expired session token"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/sessions/delete-all [delete]
func DeleteAllSessionsHandler(c echo.Context) error {
	logger := c.Logger()

	user, err := middlewares.GetAuthenticatedUser(c)
	if err != nil {
		logger.Error("Failed to get authenticated user:", err)
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired authentication token, please login again",
		}
	}

	currentSession, currentSessionExists := c.Get("session").(models.Session)
	if !currentSessionExists {
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Current session not found",
		}
	}

	var totalSessions int64
	if err := db.Conn.Model(&models.Session{}).Where("user_id = ?", user.ID).Count(&totalSessions).Error; err != nil {
		logger.Errorf("Failed to count sessions: %v", err)
		return echo.ErrInternalServerError
	}

	result := db.Conn.Unscoped().Where("user_id = ? AND id != ?", user.ID, currentSession.ID).Delete(&models.Session{})
	if result.Error != nil {
		logger.Errorf("Failed to delete sessions: %v", result.Error)
		return echo.ErrInternalServerError
	}

	deletedCount := result.RowsAffected

	logger.Infof("Deleted %d sessions for user %d, keeping current session %d", deletedCount, user.ID, currentSession.ID)
	return c.JSON(http.StatusOK, DeleteAllSessionsResponse{
		Message:       "All other sessions deleted successfully",
		DeletedCount:  int(deletedCount),
		TotalSessions: int(totalSessions),
	})
}

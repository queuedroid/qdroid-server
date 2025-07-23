// SPX-License-Identifier: GPL-3.0-only

package handlers

import (
	"fmt"
	"net/http"
	"qdroid-server/db"
	"qdroid-server/middlewares"
	"qdroid-server/models"

	"github.com/labstack/echo/v4"
)

func CreateEventLogHandler(eventLog models.EventLog) error {
	if err := db.Conn.Create(&eventLog).Error; err != nil {
		return fmt.Errorf("failed to create event log: %w", err)
	}
	return nil
}

func LogEventHandler(
	category *models.EventCategory,
	status *models.EventStatus,
	exchangeID *string,
	to *string,
	userID uint,
	description *string,
	queueName *string,
	queueID *string,
	carrier *string,
) error {
	eventLog := models.EventLog{
		Category:    category,
		Status:      status,
		ExchangeID:  exchangeID,
		QueueName:   queueName,
		QueueID:     queueID,
		To:          to,
		UserID:      userID,
		Description: description,
		Carrier:     carrier,
	}
	return CreateEventLogHandler(eventLog)
}

func LogMessageEventFailureHandler(
	exchangeID *string,
	to *string,
	userID uint,
	description *string,
	queueName *string,
	queueID *string,
	carrier *string,
) error {
	status := new(models.EventStatus)
	*status = models.Failed
	category := new(models.EventCategory)
	*category = models.Message
	return LogEventHandler(category, status, exchangeID, to, userID, description, queueName, queueID, carrier)
}

func LogMessageEventSuccessHandler(
	exchangeID *string,
	to *string,
	userID uint,
	queueName *string,
	queueID *string,
	carrier *string,
) error {
	status := new(models.EventStatus)
	*status = models.Queued
	category := new(models.EventCategory)
	*category = models.Message
	return LogEventHandler(category, status, exchangeID, to, userID, nil, queueName, queueID, carrier)
}

// GetEventLogsSummaryHandler godoc
// @Summary      Get event logs summary
// @Description  Retrieves summary statistics for all event logs for the authenticated user by category and status combination. Can be filtered by category.
// @Tags         event-logs
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Param        category query   string  true  "Filter by event category (MESSAGE, PAYMENT, AUTH)"
// @Success      200 {object} EventLogSummaryResponse "Event logs summary with totals by category and status"
// @Failure      401 {object} echo.HTTPError     "Unauthorized, invalid or expired session token"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/event-logs/summary [get]
func GetEventLogsSummaryHandler(c echo.Context) error {
	logger := c.Logger()

	user, err := middlewares.GetAuthenticatedUser(c)
	if err != nil {
		logger.Error("Failed to get authenticated user:", err)
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired authentication token, please login again",
		}
	}

	category := c.QueryParam("category")
	if category == "" {
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Category parameter is required",
		}
	}

	var results []struct {
		Status string
		Count  int64
	}

	err = db.Conn.Model(&models.EventLog{}).
		Select("status, count(*) as count").
		Where("user_id = ? AND category = ?", user.ID, category).
		Group("status").
		Find(&results).Error

	if err != nil {
		logger.Error("Failed to fetch event log summary:", err)
		return &echo.HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Failed to retrieve event logs summary",
		}
	}

	var totalCount, totalQueued, totalFailed, totalPending int64

	for _, result := range results {
		totalCount += result.Count
		switch result.Status {
		case string(models.Queued):
			totalQueued = result.Count
		case string(models.Failed):
			totalFailed = result.Count
		case string(models.Pending):
			totalPending = result.Count
		}
	}

	summaryData := EventLogSummaryData{
		TotalCount:   totalCount,
		TotalQueued:  totalQueued,
		TotalFailed:  totalFailed,
		TotalPending: totalPending,
	}

	return c.JSON(http.StatusOK, EventLogSummaryResponse{
		Data:    summaryData,
		Message: "Event logs summary retrieved successfully",
	})
}

// GetEventLogsHandler godoc
// @Summary      Get event logs (paginated)
// @Description  Retrieves all event logs for the authenticated user, paginated. Supports filtering by category and status.
// @Tags         event-logs
// @Produce      json
// @Security     BearerAuth
// @Param        Authorization  header  string  true  "Bearer token for authentication. Replace <your_token_here> with a valid token."  default(Bearer <your_token_here>)
// @Param        page     query   int     false  "Page number (default 1)"
// @Param        page_size query  int     false  "Page size (default 10, max 100)"
// @Param        category query   string  false  "Filter by event category (MESSAGE, PAYMENT, AUTH)"
// @Param        status   query   string  false  "Filter by event status (PENDING, QUEUED, FAILED)"
// @Success      200 {object} EventLogListResponse "Paginated list of event logs"
// @Failure      401 {object} echo.HTTPError     "Unauthorized, invalid or expired session token"
// @Failure      500 {object} echo.HTTPError     "Internal server error"
// @Router       /v1/event-logs [get]
func GetEventLogsHandler(c echo.Context) error {
	logger := c.Logger()

	user, err := middlewares.GetAuthenticatedUser(c)
	if err != nil {
		logger.Error("Failed to get authenticated user:", err)
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired authentication token, please login again",
		}
	}

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

	query := db.Conn.Model(&models.EventLog{}).Where("user_id = ?", user.ID)

	if category := c.QueryParam("category"); category != "" {
		query = query.Where("category = ?", category)
	}

	if status := c.QueryParam("status"); status != "" {
		query = query.Where("status = ?", status)
	}

	var total int64
	var eventLogs []models.EventLog

	query.Count(&total)

	query.Order("created_at desc").
		Limit(pageSize).
		Offset((page - 1) * pageSize).
		Find(&eventLogs)

	var data []EventLogDetails = []EventLogDetails{}
	for _, log := range eventLogs {
		var category, status *string
		if log.Category != nil {
			cat := string(*log.Category)
			category = &cat
		}
		if log.Status != nil {
			stat := string(*log.Status)
			status = &stat
		}

		data = append(data, EventLogDetails{
			EID:         log.EID.String(),
			Category:    category,
			Status:      status,
			ExchangeID:  log.ExchangeID,
			QueueName:   log.QueueName,
			QueueID:     log.QueueID,
			Description: log.Description,
			To:          log.To,
			Carrier:     log.Carrier,
			CreatedAt:   log.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:   log.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))
	return c.JSON(http.StatusOK, EventLogListResponse{
		Data: data,
		Pagination: PaginationDetails{
			Page:       page,
			PageSize:   pageSize,
			Total:      total,
			TotalPages: totalPages,
		},
		Message: "Event logs retrieved successfully",
	})
}

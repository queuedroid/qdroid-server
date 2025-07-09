// SPX-License-Identifier: GPL-3.0-only

package handlers

import (
	"fmt"
	"qdroid-server/db"
	"qdroid-server/models"
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

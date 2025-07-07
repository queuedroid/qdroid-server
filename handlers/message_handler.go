// SPX-License-Identifier: GPL-3.0-only

package handlers

import (
	"fmt"
	"net/http"
	"qdroid-server/commons"
	"qdroid-server/models"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/nyaruka/phonenumbers"
)

func SendMessageHandler(c echo.Context) error {
	logger := c.Logger()

	// rmqClient, err := rabbitmq.NewClient(rabbitmq.RabbitMQConfig{})
	// if err != nil {
	// 	logger.Error("Failed to initialize RabbitMQ client:", err)
	// 	return echo.ErrInternalServerError
	// }

	session, ok := c.Get("session").(models.Session)
	if !ok {
		logger.Error("Session not found in context.")
		return &echo.HTTPError{
			Code:    http.StatusUnauthorized,
			Message: "Invalid or expired session token, please login again",
		}
	}

	var req SendMessageRequest
	if err := c.Bind(&req); err != nil {
		logger.Error("Invalid send message request payload:", err)
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Invalid request payload, please ensure it is well-formed and has content-type application/json header",
		}
	}

	if req.ExchangeID == "" {
		logger.Error("ExchangeID is required.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "exchange_id field is required",
		}
	}

	if req.Content == "" {
		logger.Error("Content is required.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "content field is required",
		}
	}

	if req.PhoneNumber == "" {
		logger.Error("PhoneNumber is required.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "phone_number field is required",
		}
	}

	parsedNumber, err := phonenumbers.Parse(req.PhoneNumber, "")
	if err != nil {
		logger.Error("Failed to parse phone number: ", err)
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "phone_number field must be a valid E.164 phone number. Please ensure it starts with a '+' followed by the country code and national number.",
		}
	}

	if !phonenumbers.IsValidNumber(parsedNumber) {
		logger.Error("Invalid phone number format.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "phone_number field must be a valid E.164 phone number. Please ensure it starts with a '+' followed by the country code and national number.",
		}
	}

	var queueID string
	var status string
	logFailure := func(msg string) error {
		logger.Error(msg)
		if err := LogMessageEventFailureHandler(
			&req.ExchangeID,
			&req.PhoneNumber,
			session.UserID,
			&msg,
			nil,
			nil,
		); err != nil {
			logger.Error("Failed to create event log: ", err)
			return echo.ErrInternalServerError
		}
		return nil
	}

	if req.QueueID == nil {
		region := phonenumbers.GetRegionCodeForNumber(parsedNumber)
		carrier, prefix, err := phonenumbers.GetCarrierWithPrefixForNumber(parsedNumber, "en")
		if err != nil {
			errorMsg := fmt.Sprintf("Carrier information not found for phone number: %s - %v", req.PhoneNumber, err)
			status = "failed"
			if err := logFailure(errorMsg); err != nil {
				return err
			}
		}

		if carrier == "" {
			errorMsg := fmt.Sprint("Carrier information not found for phone number: ", req.PhoneNumber)
			status = "failed"
			if err := logFailure(errorMsg); err != nil {
				return err
			}
		}

		if prefix == 0 {
			errorMsg := fmt.Sprint("Prefix information not found for phone number: ", req.PhoneNumber)
			status = "failed"
			if err := logFailure(errorMsg); err != nil {
				return err
			}
		}

		countryCode := phonenumbers.GetCountryCodeForRegion(region)
		countryName, err := phonenumbers.GetGeocodingForNumber(parsedNumber, "en")
		if err != nil {
			errorMsg := fmt.Sprintf("Geocoding information not found for phone number: %s - %v", req.PhoneNumber, err)
			status = "failed"
			if err := logFailure(errorMsg); err != nil {
				return err
			}
		}

		logger.Printf("Phone number region: %s", region)
		logger.Printf("Phone number carrier: %s", carrier)
		logger.Printf("Phone number prefix: %d", prefix)
		logger.Printf("Phone number country code: %d", countryCode)
		logger.Printf("Phone number country name: %s", countryName)

		mccmncList := commons.MCCMNCIndex.LookupByPrefix(fmt.Sprintf("%d", prefix))
		logger.Printf("MCCMNC List: %+v", mccmncList)
		if len(mccmncList) == 0 {
			errorMsg := fmt.Sprintf("MCCMNC not found for phone number: %s", req.PhoneNumber)
			status = "failed"
			if err := logFailure(errorMsg); err != nil {
				return err
			}
		}

		if status == "failed" {
			return c.JSON(http.StatusOK, ReturnMessage{
				Message: "Check your logs for more details.",
				Status:  &status,
			})
		}

		mccmnc := mccmncList[0].MCCMNC
		queueID = fmt.Sprintf("%s.%d.%d", req.ExchangeID, countryCode, mccmnc)
	} else {
		queueID = *req.QueueID
	}

	queueName := strings.ReplaceAll(queueID, ".", "_")
	fmt.Print("Queue ID: ", queueID)

	err = LogMessageEventSuccessHandler(
		&req.ExchangeID,
		&req.PhoneNumber,
		session.UserID,
		&queueName,
		&queueID,
	)
	if err != nil {
		logger.Error("Failed to create event log: ", err)
		return echo.ErrInternalServerError
	}

	status = "queued"
	return c.JSON(http.StatusOK, ReturnMessage{
		Message: "Check your logs for more details.",
		Status:  &status,
	})
}

// SPX-License-Identifier: GPL-3.0-only

package handlers

import (
	"fmt"
	"net/http"
	"qdroid-server/commons"

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

	// session, ok := c.Get("session").(models.Session)
	// if !ok {
	// 	logger.Error("Session not found in context.")
	// 	return &echo.HTTPError{
	// 		Code:    http.StatusUnauthorized,
	// 		Message: "Invalid or expired session token, please login again",
	// 	}
	// }

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
		logger.Error("Failed to parse phone number:", err)
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "phone_number field must be a valid E.164 phone number. Please ensure it starts with a '+' followed by the country code and national number.",
		}
	}
	isPhoneNumberValid := phonenumbers.IsValidNumber(parsedNumber)

	if !isPhoneNumberValid {
		logger.Error("Invalid phone number format.")
		return &echo.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "phone_number field must be a valid E.164 phone number. Please ensure it starts with a '+' followed by the country code and national number.",
		}
	}

	region := phonenumbers.GetRegionCodeForNumber(parsedNumber)
	carrier, prefix, err := phonenumbers.GetCarrierWithPrefixForNumber(parsedNumber, "en")
	if err != nil {
		logger.Error("Failed to get carrier information:", err)
		return echo.ErrInternalServerError
	}
	if carrier == "" {
		logger.Error("Carrier information not found.")
		return echo.ErrInternalServerError
	}
	if prefix == 0 {
		logger.Error("Prefix information not found.")
		return echo.ErrInternalServerError
	}
	countryCode := phonenumbers.GetCountryCodeForRegion(region)
	countryName, err := phonenumbers.GetGeocodingForNumber(parsedNumber, "en")

	if err != nil {
		logger.Error("Failed to get country information:", err)
		return echo.ErrInternalServerError
	}

	logger.Printf("Phone number region: %s", region)
	logger.Printf("Phone number carrier: %s", carrier)
	logger.Printf("Phone number prefix: %d", prefix)
	logger.Printf("Phone number country code: %d", countryCode)
	logger.Printf("Phone number country name: %s", countryName)

	results := commons.MCCMNCIndex.LookupByPrefix(fmt.Sprintf("%d", prefix))

	logger.Printf("PLMN: %+v", results[0])
	return c.JSON(http.StatusOK, ReturnMessage{
		Message: "Message queued successfully, Check your logs for more details.",
	})

	// if req.RoutingKey == "" {
	// 	req.RoutingKey = fmt.Sprintf("%s.%s.%s", req.ExchangeID, parsedNumber.CountryCode, parsedNumber.Carr)
	// }

}

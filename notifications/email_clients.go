// SPDX-License-Identifier: GPL-3.0-only

package notifications

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"qdroid-server/commons"
	"time"
)

func ZeptoMailClient(data NotificationData) error {
	commons.Logger.Debug("Sending email via ZeptoMail")

	apiKey := commons.GetEnv("ZEPTO_MAIL_API_KEY")
	if apiKey == "" {
		return fmt.Errorf("ZEPTO_MAIL_API_KEY environment variable is not set")
	}

	baseURL := commons.GetEnv("ZEPTO_MAIL_BASE_URL")
	if baseURL == "" {
		return fmt.Errorf("ZEPTO_MAIL_BASE_URL environment variable is not set")
	}

	fromEmail := commons.GetEnv("ZEPTO_MAIL_FROM_EMAIL")
	if fromEmail == "" {
		return fmt.Errorf("ZEPTO_MAIL_FROM_EMAIL environment variable is not set")
	}
	fromName := commons.GetEnv("ZEPTO_MAIL_FROM_NAME")
	if fromName == "" {
		return fmt.Errorf("ZEPTO_MAIL_FROM_NAME environment variable is not set")
	}

	to := data.To
	if to == "" {
		return fmt.Errorf("'to' field is required")
	}
	toName := data.ToName
	templateAlias := data.Template
	if templateAlias == "" {
		return fmt.Errorf("'template' field is required")
	}

	emailRequest := ZeptoMailRequest{
		From: ZeptoMailAddress{
			Address: fromEmail,
			Name:    &fromName,
		},
		To: []ZeptoMailRecipient{
			{
				EmailAddress: ZeptoMailAddress{
					Address: to,
					Name:    toName,
				},
			},
		},
		TemplateAlias: templateAlias,
		MergeInfo:     data.Variables,
	}

	jsonData, err := json.Marshal(emailRequest)
	if err != nil {
		commons.Logger.Error("Failed to marshal email request:", err)
		return fmt.Errorf("failed to marshal email request: %w", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest("POST", baseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		commons.Logger.Error("Failed to create HTTP request:", err)
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Zoho-enczapikey "+apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		commons.Logger.Error("Failed to send email request:", err)
		return fmt.Errorf("failed to send email request: %w", err)
	}
	defer resp.Body.Close()

	var zeptoResponse ZeptoMailResponse
	if err := json.NewDecoder(resp.Body).Decode(&zeptoResponse); err != nil {
		commons.Logger.Error("Failed to decode response:", err)
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if zeptoResponse.Error != nil {
		commons.Logger.Errorf("ZeptoMail API returned error: %s", zeptoResponse.Error.Message)
		return fmt.Errorf("- status: %d\n- message: %s\n- details: %v",
			resp.StatusCode,
			zeptoResponse.Error.Message,
			zeptoResponse.Error.Details,
		)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		commons.Logger.Error("ZeptoMail API returned error:", zeptoResponse.Message)
		return fmt.Errorf("ZeptoMail API error:\n- status: %d\n- message: %s", resp.StatusCode, zeptoResponse.Message)
	}

	if len(zeptoResponse.Data) > 0 {
		commons.Logger.Infof("ZeptoMail response data: %v", zeptoResponse.Data)
	}

	commons.Logger.Info("Email sent successfully via ZeptoMail")
	return nil
}

func MockEmailClient(data NotificationData) error {
	commons.Logger.Info("=== MOCK EMAIL NOTIFICATION ===")
	commons.Logger.Infof("To: %s", data.To)
	if data.ToName != nil {
		commons.Logger.Infof("To Name: %s", *data.ToName)
	}
	commons.Logger.Infof("Template: %s", data.Template)

	if len(data.Variables) > 0 {
		commons.Logger.Info("Variables:")
		for key, value := range data.Variables {
			commons.Logger.Infof("  %s: %v", key, value)
		}
	}

	commons.Logger.Info("=== EMAIL MOCK COMPLETE ===")
	return nil
}

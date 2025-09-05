// SPDX-License-Identifier: GPL-3.0-only

package notifications

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"qdroid-server/commons"
	"strconv"

	"gopkg.in/gomail.v2"
)

func MockEmailClient(data NotificationData) error {
	commons.Logger.Info("=== MOCK EMAIL NOTIFICATION ===")
	commons.Logger.Infof("To: %s", data.To)
	if data.ToName != nil {
		commons.Logger.Infof("To Name: %s", *data.ToName)
	}
	commons.Logger.Infof("Subject: %s", data.Subject)
	commons.Logger.Infof("Template: %s", data.Template)

	if len(data.Variables) > 0 {
		commons.Logger.Info("Variables:")
		for key, value := range data.Variables {
			commons.Logger.Infof("  %s: %v", key, value)
		}
	}

	if data.Template != "" {
		htmlBody, err := loadAndRenderTemplate(data.Template, data.Variables)
		if err != nil {
			commons.Logger.Errorf("Failed to render template: %v", err)
			return fmt.Errorf("failed to render template: %w", err)
		}

		commons.Logger.Info("=== RENDERED EMAIL CONTENT ===")
		fmt.Println(htmlBody)
		commons.Logger.Info("=== END EMAIL CONTENT ===")
	}

	commons.Logger.Info("=== EMAIL MOCK COMPLETE ===")
	return nil
}

func SMTPClient(data NotificationData) error {
	commons.Logger.Debug("Sending email via SMTP")

	smtpHost := commons.GetEnv("SMTP_HOST")
	if smtpHost == "" {
		return fmt.Errorf("SMTP_HOST environment variable is not set")
	}

	smtpPort := commons.GetEnv("SMTP_PORT")
	if smtpPort == "" {
		return fmt.Errorf("SMTP_PORT environment variable is not set")
	}

	username := commons.GetEnv("SMTP_USERNAME")
	if username == "" {
		return fmt.Errorf("SMTP_USERNAME environment variable is not set")
	}

	password := commons.GetEnv("SMTP_PASSWORD")
	if password == "" {
		return fmt.Errorf("SMTP_PASSWORD environment variable is not set")
	}

	fromEmail := commons.GetEnv("SMTP_FROM_EMAIL")
	if fromEmail == "" {
		return fmt.Errorf("SMTP_FROM_EMAIL environment variable is not set")
	}

	fromName := commons.GetEnv("SMTP_FROM_NAME")
	if fromName == "" {
		fromName = "QueueDroid"
	}

	if data.To == "" {
		return fmt.Errorf("'to' field is required")
	}

	if data.Subject == "" {
		return fmt.Errorf("'subject' field is required")
	}

	if data.Template == "" {
		return fmt.Errorf("'template' field is required")
	}

	htmlBody, err := loadAndRenderTemplate(data.Template, data.Variables)
	if err != nil {
		return fmt.Errorf("failed to load template: %w", err)
	}

	port, err := strconv.Atoi(smtpPort)
	if err != nil {
		return fmt.Errorf("invalid SMTP port: %s", smtpPort)
	}

	message := gomail.NewMessage()
	message.SetHeader("From", message.FormatAddress(fromEmail, fromName))
	message.SetHeader("To", message.FormatAddress(data.To, *data.ToName))
	message.SetHeader("Subject", data.Subject)
	message.SetBody("text/html", htmlBody)

	dialer := gomail.NewDialer(smtpHost, port, username, password)
	dialer.TLSConfig = &tls.Config{
		ServerName:         smtpHost,
		InsecureSkipVerify: false,
	}

	if err := dialer.DialAndSend(message); err != nil {
		commons.Logger.Error("Failed to send email via SMTP:", err)
		return fmt.Errorf("failed to send email via SMTP: %w", err)
	}

	commons.Logger.Info("Email sent successfully via SMTP")
	return nil
}

func loadAndRenderTemplate(templateName string, variables map[string]any) (string, error) {
	templatePath := filepath.Join("email_templates", templateName+".html")

	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		commons.Logger.Warnf("Template file not found: %s.", templatePath)
		return "", fmt.Errorf("template file not found: %s", templatePath)
	}

	templateContent, err := os.ReadFile(templatePath)
	if err != nil {
		return "", fmt.Errorf("failed to read template file %s: %w", templatePath, err)
	}

	tmpl, err := template.New(templateName).Parse(string(templateContent))
	if err != nil {
		return "", fmt.Errorf("failed to parse template %s: %w", templateName, err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, variables); err != nil {
		return "", fmt.Errorf("failed to execute template %s: %w", templateName, err)
	}

	return buf.String(), nil
}

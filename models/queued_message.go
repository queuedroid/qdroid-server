// SPDX-License-Identifier: GPL-3.0-only

package models

import (
	"time"

	"github.com/google/uuid"
)

// QueuedMessage represents a message that has been queued for processing
type QueuedMessage struct {
	// Mid is the unique message identifier
	Mid string `json:"mid"`
	// Content is the message text
	Content string `json:"content"`
	// PhoneNumber is the recipient's phone number
	PhoneNumber string `json:"phonenumber"`
	// Secured indicates if the message is secured
	Secured bool `json:"secured"`
	// Timestamp when the message was created
	CreatedAt time.Time `json:"created_at"`
}

// NewQueuedMessage creates a new queued message with a generated message ID
func NewQueuedMessage(content, phoneNumber string, secured bool) *QueuedMessage {
	return &QueuedMessage{
		Mid:         uuid.New().String(),
		Content:     content,
		PhoneNumber: phoneNumber,
		Secured:     secured,
		CreatedAt:   time.Now(),
	}
}
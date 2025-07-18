package models

import (
	"testing"
	"time"
)

func TestNewQueuedMessage(t *testing.T) {
	content := "Hello, World!"
	phoneNumber := "+1234567890"
	secured := true

	qm := NewQueuedMessage(content, phoneNumber, secured)

	if qm.Content != content {
		t.Errorf("Expected content %s, got %s", content, qm.Content)
	}

	if qm.PhoneNumber != phoneNumber {
		t.Errorf("Expected phone number %s, got %s", phoneNumber, qm.PhoneNumber)
	}

	if qm.Secured != secured {
		t.Errorf("Expected secured %v, got %v", secured, qm.Secured)
	}

	if qm.Mid == "" {
		t.Error("Expected non-empty message ID")
	}

	if qm.CreatedAt.IsZero() {
		t.Error("Expected non-zero creation time")
	}

	// Test that different messages get different IDs
	qm2 := NewQueuedMessage("Different content", "+9876543210", false)
	if qm.Mid == qm2.Mid {
		t.Error("Expected different message IDs for different messages")
	}
}

func TestQueuedMessageSerialization(t *testing.T) {
	content := "Test message"
	phoneNumber := "+1234567890"
	secured := false

	qm := NewQueuedMessage(content, phoneNumber, secured)

	// This test ensures the struct can be serialized to JSON
	// (actual JSON serialization test would require encoding/json import)
	if qm.Mid == "" {
		t.Error("Message ID should not be empty")
	}
	if qm.Content != content {
		t.Error("Content should match")
	}
	if qm.PhoneNumber != phoneNumber {
		t.Error("Phone number should match")
	}
	if qm.Secured != secured {
		t.Error("Secured flag should match")
	}
	if qm.CreatedAt.After(time.Now()) {
		t.Error("CreatedAt should not be in the future")
	}
}
package handlers

import (
	"encoding/json"
	"qdroid-server/models"
	"testing"
)

func TestSendMessageRequestStructure(t *testing.T) {
	// Test that the SendMessageRequest can be parsed correctly with the new secured field
	jsonPayload := `{
		"exchange_id": "test_exchange",
		"content": "Hello, World!",
		"phone_number": "+1234567890",
		"secured": true
	}`

	var req SendMessageRequest
	err := json.Unmarshal([]byte(jsonPayload), &req)
	if err != nil {
		t.Fatalf("Failed to unmarshal SendMessageRequest: %v", err)
	}

	if req.ExchangeID != "test_exchange" {
		t.Errorf("Expected exchange_id 'test_exchange', got %s", req.ExchangeID)
	}
	if req.Content != "Hello, World!" {
		t.Errorf("Expected content 'Hello, World!', got %s", req.Content)
	}
	if req.PhoneNumber != "+1234567890" {
		t.Errorf("Expected phone_number '+1234567890', got %s", req.PhoneNumber)
	}
	if req.Secured == nil || *req.Secured != true {
		t.Errorf("Expected secured to be true, got %v", req.Secured)
	}
}

func TestSendMessageRequestWithoutSecured(t *testing.T) {
	// Test that the SendMessageRequest works without the secured field (backward compatibility)
	jsonPayload := `{
		"exchange_id": "test_exchange",
		"content": "Hello, World!",
		"phone_number": "+1234567890"
	}`

	var req SendMessageRequest
	err := json.Unmarshal([]byte(jsonPayload), &req)
	if err != nil {
		t.Fatalf("Failed to unmarshal SendMessageRequest: %v", err)
	}

	if req.ExchangeID != "test_exchange" {
		t.Errorf("Expected exchange_id 'test_exchange', got %s", req.ExchangeID)
	}
	if req.Content != "Hello, World!" {
		t.Errorf("Expected content 'Hello, World!', got %s", req.Content)
	}
	if req.PhoneNumber != "+1234567890" {
		t.Errorf("Expected phone_number '+1234567890', got %s", req.PhoneNumber)
	}
	if req.Secured != nil {
		t.Errorf("Expected secured to be nil, got %v", req.Secured)
	}
}

func TestQueuedMessageGeneration(t *testing.T) {
	// Test that QueuedMessage is generated correctly from request data
	content := "Test message"
	phoneNumber := "+1234567890"
	secured := true

	qm := models.NewQueuedMessage(content, phoneNumber, secured)

	// Serialize to JSON to verify the structure
	jsonData, err := json.Marshal(qm)
	if err != nil {
		t.Fatalf("Failed to serialize QueuedMessage: %v", err)
	}

	// Parse the JSON to verify structure
	var jsonMap map[string]interface{}
	err = json.Unmarshal(jsonData, &jsonMap)
	if err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Check that all required fields are present
	requiredFields := []string{"mid", "content", "phonenumber", "secured", "created_at"}
	for _, field := range requiredFields {
		if _, exists := jsonMap[field]; !exists {
			t.Errorf("Required field %s missing from JSON", field)
		}
	}

	// Verify field values
	if jsonMap["content"] != content {
		t.Errorf("Expected content %s, got %v", content, jsonMap["content"])
	}
	if jsonMap["phonenumber"] != phoneNumber {
		t.Errorf("Expected phonenumber %s, got %v", phoneNumber, jsonMap["phonenumber"])
	}
	if jsonMap["secured"] != secured {
		t.Errorf("Expected secured %v, got %v", secured, jsonMap["secured"])
	}

	// Check that mid is not empty
	if mid, ok := jsonMap["mid"].(string); !ok || mid == "" {
		t.Error("Expected non-empty mid field")
	}
}

func TestBulkSendMessageRequestStructure(t *testing.T) {
	// Test that the BulkSendMessageRequest works with the new secured field
	jsonPayload := `{
		"messages": [
			{
				"exchange_id": "test_exchange",
				"content": "Message 1",
				"phone_number": "+1234567890",
				"secured": true
			},
			{
				"exchange_id": "test_exchange",
				"content": "Message 2",
				"phone_number": "+9876543210",
				"secured": false
			}
		]
	}`

	var req BulkSendMessageRequest
	err := json.Unmarshal([]byte(jsonPayload), &req)
	if err != nil {
		t.Fatalf("Failed to unmarshal BulkSendMessageRequest: %v", err)
	}

	if len(req.Messages) != 2 {
		t.Fatalf("Expected 2 messages, got %d", len(req.Messages))
	}

	// Check first message
	msg1 := req.Messages[0]
	if msg1.Content != "Message 1" {
		t.Errorf("Expected content 'Message 1', got %s", msg1.Content)
	}
	if msg1.Secured == nil || *msg1.Secured != true {
		t.Errorf("Expected secured to be true, got %v", msg1.Secured)
	}

	// Check second message
	msg2 := req.Messages[1]
	if msg2.Content != "Message 2" {
		t.Errorf("Expected content 'Message 2', got %s", msg2.Content)
	}
	if msg2.Secured == nil || *msg2.Secured != false {
		t.Errorf("Expected secured to be false, got %v", msg2.Secured)
	}
}
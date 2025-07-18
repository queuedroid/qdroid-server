package models

import (
	"encoding/json"
	"testing"
)

func TestQueuedMessageJSONSerialization(t *testing.T) {
	content := "Test message"
	phoneNumber := "+1234567890"
	secured := true

	qm := NewQueuedMessage(content, phoneNumber, secured)

	// Serialize to JSON
	jsonData, err := json.Marshal(qm)
	if err != nil {
		t.Fatalf("Failed to serialize QueuedMessage to JSON: %v", err)
	}

	// Deserialize from JSON
	var deserializedQM QueuedMessage
	err = json.Unmarshal(jsonData, &deserializedQM)
	if err != nil {
		t.Fatalf("Failed to deserialize QueuedMessage from JSON: %v", err)
	}

	// Check that all fields are preserved
	if deserializedQM.Mid != qm.Mid {
		t.Errorf("Expected Mid %s, got %s", qm.Mid, deserializedQM.Mid)
	}
	if deserializedQM.Content != qm.Content {
		t.Errorf("Expected Content %s, got %s", qm.Content, deserializedQM.Content)
	}
	if deserializedQM.PhoneNumber != qm.PhoneNumber {
		t.Errorf("Expected PhoneNumber %s, got %s", qm.PhoneNumber, deserializedQM.PhoneNumber)
	}
	if deserializedQM.Secured != qm.Secured {
		t.Errorf("Expected Secured %v, got %v", qm.Secured, deserializedQM.Secured)
	}

	// Check that JSON contains the expected fields
	var jsonMap map[string]interface{}
	err = json.Unmarshal(jsonData, &jsonMap)
	if err != nil {
		t.Fatalf("Failed to parse JSON as map: %v", err)
	}

	expectedFields := []string{"mid", "content", "phonenumber", "secured", "created_at"}
	for _, field := range expectedFields {
		if _, exists := jsonMap[field]; !exists {
			t.Errorf("Expected field %s to exist in JSON", field)
		}
	}

	// Verify the specific field values
	if jsonMap["content"] != content {
		t.Errorf("Expected content %s in JSON, got %v", content, jsonMap["content"])
	}
	if jsonMap["phonenumber"] != phoneNumber {
		t.Errorf("Expected phonenumber %s in JSON, got %v", phoneNumber, jsonMap["phonenumber"])
	}
	if jsonMap["secured"] != secured {
		t.Errorf("Expected secured %v in JSON, got %v", secured, jsonMap["secured"])
	}
}
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"qdroid-server/models"
)

// Example demonstrating the new queued message structure
func main() {
	// Example 1: Create a regular message (not secured)
	message1 := models.NewQueuedMessage(
		"Hello, this is a test message!",
		"+1234567890",
		false,
	)

	// Example 2: Create a secured message
	message2 := models.NewQueuedMessage(
		"This is a secured message containing sensitive information.",
		"+9876543210",
		true,
	)

	// Serialize to JSON (this is what would be sent to RabbitMQ)
	jsonData1, err := json.MarshalIndent(message1, "", "  ")
	if err != nil {
		log.Fatal("Failed to serialize message1:", err)
	}

	jsonData2, err := json.MarshalIndent(message2, "", "  ")
	if err != nil {
		log.Fatal("Failed to serialize message2:", err)
	}

	fmt.Println("Example 1 - Regular Message:")
	fmt.Println(string(jsonData1))
	fmt.Println("\nExample 2 - Secured Message:")
	fmt.Println(string(jsonData2))

	// Demonstrate deserialization
	var deserializedMessage models.QueuedMessage
	err = json.Unmarshal(jsonData1, &deserializedMessage)
	if err != nil {
		log.Fatal("Failed to deserialize message:", err)
	}

	fmt.Printf("\nDeserialized message ID: %s\n", deserializedMessage.Mid)
	fmt.Printf("Content: %s\n", deserializedMessage.Content)
	fmt.Printf("Phone Number: %s\n", deserializedMessage.PhoneNumber)
	fmt.Printf("Secured: %v\n", deserializedMessage.Secured)
	fmt.Printf("Created At: %v\n", deserializedMessage.CreatedAt)
}
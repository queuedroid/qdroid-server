# Queued Message Structure Update

This document describes the changes made to structure queued messages with the required fields: `mid`, `content`, `phonenumber`, and `secured`.

## Changes Made

### 1. New QueuedMessage Model (`models/queued_message.go`)

A new `QueuedMessage` struct has been created with the following fields:

- `mid`: String - Unique message identifier (UUID)
- `content`: String - The message text
- `phonenumber`: String - Recipient's phone number (note: JSON field uses "phonenumber" not "phone_number")
- `secured`: Boolean - Indicates if the message is secured
- `created_at`: Time - Timestamp when the message was created

### 2. Updated SendMessageRequest (`handlers/types.go`)

The `SendMessageRequest` struct now includes an optional `secured` field:

```go
type SendMessageRequest struct {
    ExchangeID  string  `json:"exchange_id"`
    Content     string  `json:"content"`
    PhoneNumber string  `json:"phone_number"`
    QueueID     *string `json:"queue_id"`
    Secured     *bool   `json:"secured"`  // New field
}
```

### 3. Updated Message Processing (`handlers/message_handler.go`)

The `processMessage` function now:

1. Creates a structured `QueuedMessage` object
2. Generates a unique message ID (UUID)
3. Handles the `secured` flag (defaults to `false` if not provided)
4. Serializes the message to JSON before publishing to RabbitMQ
5. Sets the content type to "application/json"

## API Usage

### Single Message Request

```json
{
  "exchange_id": "ex_12345",
  "content": "Hello, World!",
  "phone_number": "+1234567890",
  "secured": true
}
```

### Bulk Message Request

```json
{
  "messages": [
    {
      "exchange_id": "ex_12345",
      "content": "Message 1",
      "phone_number": "+1234567890",
      "secured": false
    },
    {
      "exchange_id": "ex_12345",
      "content": "Secure Message 2",
      "phone_number": "+9876543210",
      "secured": true
    }
  ]
}
```

## Message Format in RabbitMQ

Messages are now published to RabbitMQ with the following structured JSON format:

```json
{
  "mid": "f07391ee-1383-4d84-92bb-c21f9f73fecc",
  "content": "Hello, this is a test message!",
  "phonenumber": "+1234567890",
  "secured": false,
  "created_at": "2025-07-18T11:22:56.637565778Z"
}
```

## Backward Compatibility

- The `secured` field is optional in the API request
- If not provided, it defaults to `false`
- Existing API consumers will continue to work without modifications
- The phone number field in the API request remains `phone_number` while the queued message uses `phonenumber`

## Testing

Tests have been added to verify:

1. QueuedMessage creation and serialization
2. JSON serialization/deserialization
3. API request parsing with and without the `secured` field
4. Bulk message processing

Run tests with:
```bash
go test ./models -v
go test ./handlers -v
```

## Example Usage

See `examples/message_structure_demo.go` for a complete example of how the new message structure works.
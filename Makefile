.PHONY: setup dev run docs build start consumer

setup:
	go mod download
	@if [ ! -f .env ]; then cp .env.example .env; fi

dev:
	@if [ ! -f mcc_mnc.json ]; then \
		echo "MCC/MNC data not found. Fetching..."; \
		make fetch-mccmnc; \
	fi
	go run server.go --debug --migrate-db --env-file .env

run:
	go run server.go --env-file .env

docs:
	swag init -g server.go --pd --parseInternal

build:
	go build -o qdroid-server server.go

start:
	./qdroid-server --env-file .env

fetch-mccmnc:
	curl -o mcc_mnc.json https://raw.githubusercontent.com/ajamous/OpenMSISDNMapper/refs/heads/main/OpenMSISDNMapper.json

consumer:
	@echo "Starting QDroid Consumer CLI..."
	@echo "Please provide the following information:"
	@read -p "AMQP URL [amqp://guest:guest@localhost]: " AMQP_URL; \
	AMQP_URL=$${AMQP_URL:-amqp://guest:guest@localhost}; \
	read -p "Exchange name (required): " EXCHANGE; \
	if [ -z "$$EXCHANGE" ]; then \
		echo "Error: Exchange name is required"; \
		exit 1; \
	fi; \
	read -p "Binding key (required): " BINDING_KEY; \
	if [ -z "$$BINDING_KEY" ]; then \
		echo "Error: Binding key is required"; \
		exit 1; \
	fi; \
	read -p "Queue name (optional): " QUEUE_NAME; \
	echo "Starting consumer with:"; \
	echo "  URL: $$AMQP_URL"; \
	echo "  Exchange: $$EXCHANGE"; \
	echo "  Binding Key: $$BINDING_KEY"; \
	echo "  Queue: $$QUEUE_NAME"; \
	echo ""; \
	go run ./cmd/consumercli.go -url "$$AMQP_URL" -exchange "$$EXCHANGE" -binding-key "$$BINDING_KEY" -queue "$$QUEUE_NAME"

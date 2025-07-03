.PHONY: setup dev run docs build start

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

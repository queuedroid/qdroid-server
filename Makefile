.PHONY: setup dev run docs build start

setup:
	go mod download
	@if [ ! -f .env ]; then cp .env.example .env; fi

dev:
	go run server.go --debug --migrate-db --env-file .env

run:
	go run server.go --env-file .env

docs:
	swag init -g server.go --pd --parseInternal

build:
	go build -o qdroid-server server.go

start:
	./qdroid-server --env-file .env

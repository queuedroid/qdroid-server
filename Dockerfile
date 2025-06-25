FROM golang:1.24

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go install github.com/swaggo/swag/cmd/swag@latest
RUN swag init -g server.go --pd --parseInternal
RUN go build -v -o qdroid-server server.go

CMD ["./qdroid-server"]

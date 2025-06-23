FROM golang:1.24

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -v -o qdroid-server server.go

CMD ["./qdroid-server"]

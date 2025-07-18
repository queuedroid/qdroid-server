FROM golang:1.24

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -v -o qdroid-server server.go
RUN make fetch-mccmnc

CMD ["./qdroid-server"]

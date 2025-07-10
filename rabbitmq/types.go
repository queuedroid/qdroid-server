// SPDX-License-Identifier: GPL-3.0-only

package rabbitmq

import (
	"net/http"
	"net/url"

	amqp "github.com/rabbitmq/amqp091-go"
)

type RabbitMQConfig struct {
	httpURL  string
	amqpURL  string
	username string
	password string
}

type Client struct {
	HTTPURL     *url.URL
	AMQPURL     *url.URL
	Username    string
	Password    string
	HTTPClient  *http.Client
	AMQPConn    *amqp.Connection
	AMQPChannel *amqp.Channel
}

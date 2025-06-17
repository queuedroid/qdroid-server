// SPDX-License-Identifier: GPL-3.0-only

package rabbitmq

import (
	"net/http"
	"net/url"
)

type RabbitMQConfig struct {
	baseURL  string
	username string
	password string
}

type Client struct {
	BaseURL    *url.URL
	Username   string
	Password   string
	HTTPClient *http.Client
}

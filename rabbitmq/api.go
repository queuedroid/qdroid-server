// SPDX-License-Identifier: GPL-3.0-only

package rabbitmq

import (
	"fmt"
	"net/http"
	"net/url"
	"qdroid-server/commons"
	"time"
)

func NewClient(c RabbitMQConfig) (*Client, error) {
	if c.baseURL == "" {
		c.baseURL = commons.GetEnv("RABBITMQ_API_URL", "http://localhost:15672")
	}
	if c.username == "" {
		c.username = commons.GetEnv("RABBITMQ_USERNAME", "guest")
	}
	if c.password == "" {
		c.password = commons.GetEnv("RABBITMQ_PASSWORD", "guest")
	}

	parsedURL, err := url.Parse(c.baseURL)
	if err != nil {
		commons.Logger.Error("Failed to parse RabbitMQ API base URL:", err)
		return nil, err
	}
	commons.Logger.Debugf("RabbitMQ API client initialized for %s", c.baseURL)
	return &Client{
		BaseURL:    parsedURL,
		Username:   c.username,
		Password:   c.password,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (c *Client) CreateVhost(vhost string) error {
	commons.Logger.Debugf("Creating RabbitMQ vhost: %s", vhost)
	rel := &url.URL{Path: fmt.Sprintf("/api/vhosts/%s", url.PathEscape(vhost))}
	u := c.BaseURL.ResolveReference(rel)
	req, err := http.NewRequest("PUT", u.String(), nil)
	if err != nil {
		commons.Logger.Error("Failed to create HTTP request for vhost creation:", err)
		return err
	}
	req.SetBasicAuth(c.Username, c.Password)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		commons.Logger.Error("HTTP request to create vhost failed:", err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		commons.Logger.Errorf("Failed to create vhost %s: %s", vhost, resp.Status)
		return fmt.Errorf("failed to create vhost: %s", resp.Status)
	}
	commons.Logger.Infof("RabbitMQ vhost created: %s", vhost)
	return nil
}

func (c *Client) DeleteVhost(vhost string) error {
	commons.Logger.Debugf("Deleting RabbitMQ vhost: %s", vhost)
	rel := &url.URL{Path: fmt.Sprintf("/api/vhosts/%s", url.PathEscape(vhost))}
	u := c.BaseURL.ResolveReference(rel)
	req, err := http.NewRequest("DELETE", u.String(), nil)
	if err != nil {
		commons.Logger.Error("Failed to create HTTP request for vhost deletion:", err)
		return err
	}
	req.SetBasicAuth(c.Username, c.Password)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		commons.Logger.Error("HTTP request to delete vhost failed:", err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		commons.Logger.Errorf("Failed to delete vhost %s: %s", vhost, resp.Status)
		return fmt.Errorf("failed to delete vhost: %s", resp.Status)
	}
	commons.Logger.Infof("RabbitMQ vhost deleted: %s", vhost)
	return nil
}

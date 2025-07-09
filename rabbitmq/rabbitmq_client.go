// SPDX-License-Identifier: GPL-3.0-only

package rabbitmq

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
		return err
	}
	req.SetBasicAuth(c.Username, c.Password)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		commons.Logger.Errorf("Failed to create vhost %s: %s", vhost, resp.Status)
		return fmt.Errorf("failed to create vhost: %s", resp.Status)
	}
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

func (c *Client) CreateUser(username, password string, tags []string) error {
	commons.Logger.Debugf("Creating RabbitMQ user: %s", username)
	rel := &url.URL{Path: fmt.Sprintf("/api/users/%s", url.PathEscape(username))}
	u := c.BaseURL.ResolveReference(rel)

	body := map[string]any{
		"password": password,
		"tags":     tags,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", u.String(), bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.Username, c.Password)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		commons.Logger.Errorf("Failed to create user %s: %s", username, resp.Status)
		return fmt.Errorf("failed to create user: %s", resp.Status)
	}
	return nil
}

func (c *Client) SetPermissions(vhost, username, configure, write, read string) error {
	commons.Logger.Debugf("Setting permissions for user %s on vhost %s", username, vhost)
	rel := &url.URL{Path: fmt.Sprintf("/api/permissions/%s/%s", url.PathEscape(vhost), url.PathEscape(username))}
	u := c.BaseURL.ResolveReference(rel)

	body := map[string]string{
		"configure": configure,
		"write":     write,
		"read":      read,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", u.String(), bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.Username, c.Password)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		commons.Logger.Errorf("Failed to set permissions for user %s on vhost %s: %s", username, vhost, resp.Status)
		return fmt.Errorf("failed to set permissions: %s", resp.Status)
	}
	return nil
}

func (c *Client) DeleteUser(username string) error {
	commons.Logger.Debugf("Deleting RabbitMQ user: %s", username)
	rel := &url.URL{Path: fmt.Sprintf("/api/users/%s", url.PathEscape(username))}
	u := c.BaseURL.ResolveReference(rel)

	req, err := http.NewRequest("DELETE", u.String(), nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.Username, c.Password)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		commons.Logger.Errorf("Failed to delete user %s: %s", username, resp.Status)
		return fmt.Errorf("failed to delete user: %s", resp.Status)
	}
	commons.Logger.Infof("RabbitMQ user deleted: %s", username)
	return nil
}

func (c *Client) CreateExchange(vhost, exchange, exchangeType string, durable bool) error {
	commons.Logger.Debugf("Creating RabbitMQ exchange: %s in vhost: %s", exchange, vhost)
	rel := &url.URL{Path: fmt.Sprintf("/api/exchanges/%s/%s", url.PathEscape(vhost), url.PathEscape(exchange))}
	u := c.BaseURL.ResolveReference(rel)

	body := map[string]any{
		"type":    exchangeType,
		"durable": durable,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", u.String(), bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.Username, c.Password)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		commons.Logger.Errorf("Failed to create exchange %s in vhost %s: %s", exchange, vhost, resp.Status)
		return fmt.Errorf("failed to create exchange: %s", resp.Status)
	}
	return nil
}

func (c *Client) DeleteExchange(vhost, exchange string) error {
	commons.Logger.Debugf("Deleting RabbitMQ exchange: %s in vhost: %s", exchange, vhost)
	rel := &url.URL{Path: fmt.Sprintf("/api/exchanges/%s/%s", url.PathEscape(vhost), url.PathEscape(exchange))}
	u := c.BaseURL.ResolveReference(rel)

	req, err := http.NewRequest("DELETE", u.String(), nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.Username, c.Password)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		commons.Logger.Errorf("Failed to delete exchange %s in vhost %s: %s", exchange, vhost, resp.Status)
		return fmt.Errorf("failed to delete exchange: %s", resp.Status)
	}
	commons.Logger.Infof("RabbitMQ exchange deleted: %s in vhost: %s", exchange, vhost)
	return nil
}

func (c *Client) GetExchangeByName(vhost, exchange string) (map[string]any, error) {
	commons.Logger.Debugf("Fetching RabbitMQ exchange: %s in vhost: %s", exchange, vhost)
	rel := &url.URL{Path: fmt.Sprintf("/api/exchanges/%s/%s", url.PathEscape(vhost), url.PathEscape(exchange))}
	u := c.BaseURL.ResolveReference(rel)

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.Username, c.Password)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		commons.Logger.Errorf("Failed to fetch exchange %s in vhost %s: %s", exchange, vhost, resp.Status)
		return nil, fmt.Errorf("failed to fetch exchange: %s", resp.Status)
	}

	var exchangeData map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&exchangeData); err != nil {
		return nil, err
	}

	commons.Logger.Infof("Fetched exchange: %s in vhost: %s", exchange, vhost)
	return exchangeData, nil
}

func (c *Client) CreateQueue(vhost, queue string, durable bool, autoDelete bool, arguments map[string]any) error {
	commons.Logger.Debugf("Creating RabbitMQ queue: %s in vhost: %s", queue, vhost)
	rel := &url.URL{Path: fmt.Sprintf("/api/queues/%s/%s", url.PathEscape(vhost), url.PathEscape(queue))}
	u := c.BaseURL.ResolveReference(rel)

	body := map[string]any{
		"durable":     durable,
		"auto_delete": autoDelete,
		"arguments":   arguments,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", u.String(), bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.Username, c.Password)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		commons.Logger.Errorf("Failed to create queue %s in vhost %s: %s", queue, vhost, resp.Status)
		return fmt.Errorf("failed to create queue: %s", resp.Status)
	}
	return nil
}

func (c *Client) BindQueue(vhost, queue, exchange, routingKey string, arguments map[string]any) error {
	commons.Logger.Debugf("Binding queue %s to exchange %s in vhost %s with routing key %s", queue, exchange, vhost, routingKey)
	rel := &url.URL{Path: fmt.Sprintf("/api/bindings/%s/e/%s/q/%s", url.PathEscape(vhost), url.PathEscape(exchange), url.PathEscape(queue))}
	u := c.BaseURL.ResolveReference(rel)

	body := map[string]any{
		"routing_key": routingKey,
		"arguments":   arguments,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", u.String(), bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.Username, c.Password)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		commons.Logger.Errorf("Failed to bind queue %s to exchange %s in vhost %s: %s", queue, exchange, vhost, resp.Status)
		return fmt.Errorf("failed to bind queue: %s", resp.Status)
	}
	return nil
}

func (c *Client) HasQueueBinding(vhost, queue, exchange string) bool {
	commons.Logger.Debugf("Checking if queue %s has binding to exchange %s in vhost %s", queue, exchange, vhost)
	rel := &url.URL{Path: fmt.Sprintf("/api/bindings/%s/e/%s/q/%s", url.PathEscape(vhost), url.PathEscape(exchange), url.PathEscape(queue))}
	u := c.BaseURL.ResolveReference(rel)

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return false
	}
	req.SetBasicAuth(c.Username, c.Password)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		commons.Logger.Debugf("Found binding between queue %s and exchange %s in vhost %s", queue, exchange, vhost)
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			commons.Logger.Errorf("Failed to read response body: %v", err)
			return false
		}

		var bindings []map[string]any
		if err := json.Unmarshal(body, &bindings); err != nil {
			commons.Logger.Errorf("Failed to parse bindings response: %v", err)
			return false
		}

		return len(bindings) > 0
	case http.StatusNotFound:
		commons.Logger.Debugf("No binding found between queue %s and exchange %s in vhost %s", queue, exchange, vhost)
		return false
	}

	commons.Logger.Errorf("Failed to check binding for queue %s and exchange %s in vhost %s: %s", queue, exchange, vhost, resp.Status)
	return false
}

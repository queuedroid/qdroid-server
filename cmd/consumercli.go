// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

type Config struct {
	AMQPURL    string
	Exchange   string
	BindingKey string
	QueueName  string
}

type Consumer struct {
	config   Config
	conn     *amqp.Connection
	channel  *amqp.Channel
	stopChan chan struct{}
}

func NewConsumer(config Config) (*Consumer, error) {
	c := &Consumer{config: config, stopChan: make(chan struct{})}

	conn, err := amqp.Dial(config.AMQPURL)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	c.conn = conn

	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("channel: %w", err)
	}
	c.channel = ch

	if err := ch.Qos(1, 0, false); err != nil {
		return nil, fmt.Errorf("qos: %w", err)
	}

	qName := config.QueueName
	if qName == "" {
		qName = strings.ReplaceAll(config.BindingKey, ".", "_")
	}

	queue, err := ch.QueueDeclare(qName, true, false, false, false, nil)
	if err != nil {
		return nil, fmt.Errorf("queue declare: %w", err)
	}

	if err := ch.QueueBind(queue.Name, config.BindingKey, config.Exchange, false, nil); err != nil {
		if ch.IsClosed() {
			if newConn, connErr := amqp.Dial(config.AMQPURL); connErr == nil {
				if newCh, chErr := newConn.Channel(); chErr == nil {
					if _, delErr := newCh.QueueDelete(queue.Name, false, false, false); delErr != nil {
						log.Printf("Failed to delete queue after binding error: %v", delErr)
					}
					newCh.Close()
				}
				newConn.Close()
			}
		} else {
			if _, delErr := ch.QueueDelete(queue.Name, false, false, false); delErr != nil {
				log.Printf("Failed to delete queue after binding error: %v", delErr)
			}
		}
		return nil, fmt.Errorf("queue bind failed (check if exchange '%s' exists): %w", config.Exchange, err)
	}

	config.QueueName = queue.Name
	c.config = config

	log.Printf("Queue ready: %s (exchange=%s, key=%s)", queue.Name, config.Exchange, config.BindingKey)
	return c, nil
}

func (c *Consumer) Start() error {
	msgs, err := c.channel.Consume(
		c.config.QueueName, "", false, false, false, false, nil,
	)
	if err != nil {
		return fmt.Errorf("consume: %w", err)
	}

	go func() {
		for {
			select {
			case msg, ok := <-msgs:
				if !ok {
					log.Println("Message channel closed")
					return
				}
				c.handleMessage(msg)
			case <-c.stopChan:
				log.Println("Stop signal received")
				return
			}
		}
	}()
	return nil
}

func (c *Consumer) handleMessage(msg amqp.Delivery) {
	log.Printf("→ Received: %s", string(msg.Body))
	time.Sleep(100 * time.Millisecond) // simulate work

	if err := msg.Ack(false); err != nil {
		log.Printf("❌ Ack failed: %v", err)
	} else {
		log.Println("✔ Ack successful")
	}
}

func (c *Consumer) Stop() {
	close(c.stopChan)
}

func (c *Consumer) Close() {
	if c.channel != nil {
		_ = c.channel.Close()
	}
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

func main() {
	cfg := Config{}
	flag.StringVar(&cfg.AMQPURL, "url", "amqp://guest:guest@localhost", "AMQP URL")
	flag.StringVar(&cfg.Exchange, "exchange", "", "Exchange name (required)")
	flag.StringVar(&cfg.BindingKey, "binding-key", "", "Binding key (required)")
	flag.StringVar(&cfg.QueueName, "queue", "", "Queue name (optional)")
	flag.Parse()

	if cfg.Exchange == "" || cfg.BindingKey == "" {
		log.Fatal("Flags -exchange and -binding-key are required.")
	}

	consumer, err := NewConsumer(cfg)
	if err != nil {
		log.Fatalf("Consumer init failed: %v", err)
	}
	defer consumer.Close()

	if err := consumer.Start(); err != nil {
		log.Fatalf("Consumer start failed: %v", err)
	}

	log.Println("Consumer is running. Press Ctrl+C to exit.")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	log.Println("Stopping consumer...")
	consumer.Stop()
	log.Println("Consumer stopped.")
}

// go run ./cmd/consumercli.go

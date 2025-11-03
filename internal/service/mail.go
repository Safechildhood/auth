package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rabbitmq/amqp091-go"
	"github.com/safechildhood/auth/internal/domain"
)

type MailService struct {
	conn    *amqp091.Connection
	channel *amqp091.Channel
}

func NewMailService(uri string) (*MailService, error) {
	conn, err := amqp091.Dial(uri)
	if err != nil {
		return nil, err
	}

	channel, err := conn.Channel()
	if err != nil {
		return nil, err
	}

	err = channel.ExchangeDeclare(
		"auth_events",
		"topic",
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		return nil, err
	}

	return &MailService{
		conn:    conn,
		channel: channel,
	}, nil
}

func (ms *MailService) SendMail(ctx context.Context, eventType domain.EventType, payload map[string]any) error {
	switch eventType {
	case domain.UserRegisterEvent, domain.UserLoginEvent, domain.UserResetPasswordEvent:
	default:
		return domain.ErrUnknownEventType
	}

	routingKey := string(eventType)

	message := make(map[string]any)

	message["type"] = routingKey
	message["payload"] = payload
	message["timestamp"] = time.Now()

	return ms.publish(ctx, "auth_events", routingKey, message)
}

func (ms *MailService) Close() error {
	if ms.channel != nil {
		if err := ms.channel.Close(); err != nil {
			return err
		}
	}

	if ms.conn != nil {
		return ms.conn.Close()
	}

	return nil
}

func (ms *MailService) publish(ctx context.Context, exchange, routingKey string, message any) error {
	body, err := json.Marshal(message)
	if err != nil {
		return err
	}

	return ms.channel.Publish(
		exchange,
		routingKey,
		false,
		false,
		amqp091.Publishing{
			ContentType: "application/json",
			Body:        body,
		},
	)
}

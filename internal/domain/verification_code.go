package domain

import (
	"time"
)

type VerificationCode struct {
	Code      string    `json:"code"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

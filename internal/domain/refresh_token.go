package domain

import (
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	TokenHash       string    `json:"token_hash"`
	UserID          uuid.UUID `json:"user_id"`
	FingerprintHash string    `json:"fingerprint_hash"`
	ExpiresAt       time.Time `json:"expires_at"`
}

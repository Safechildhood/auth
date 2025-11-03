package domain

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID               uuid.UUID `json:"id"`
	Email            string    `json:"email"`
	PasswordHash     string    `json:"password_hash"`
	Salt             string    `json:"salt"`
	SecretPhrase     string    `json:"secret_phrase"`
	SecretPhraseHint string    `json:"secret_phrase_hint"`
	FingerprintsHash []string  `json:"fingerprints_hash"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

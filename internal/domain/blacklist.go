package domain

import "time"

type BlacklistObjectType int

const (
	BlacklistAccessTokenType BlacklistObjectType = iota + 1
)

type BlacklistAccessToken struct {
	AccessTokenHash string    `json:"access_token_hash"`
	ExpiresAt       time.Time `json:"expires_at"`
}

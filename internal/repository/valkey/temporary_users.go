package valkey

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/safechildhood/auth/internal/domain"
	glide "github.com/valkey-io/valkey-glide/go/v2"
	"github.com/valkey-io/valkey-glide/go/v2/options"
)

type TemporaryUsers struct {
	client *glide.Client

	namespace string
}

func NewTemporaryUsers(client *glide.Client, namespace string) *TemporaryUsers {
	return &TemporaryUsers{
		client:    client,
		namespace: namespace,
	}
}

func (tu *TemporaryUsers) GetByEmail(ctx context.Context, email string) (domain.User, error) {
	m, err := tu.client.HGetAll(ctx, fmt.Sprintf("%s:%s", tu.namespace, email))
	if err != nil {
		return domain.User{}, err
	}

	if len(m) == 0 {
		return domain.User{}, domain.ErrUserNotFound
	}

	id, err := uuid.Parse(m["id"])
	if err != nil {
		return domain.User{}, domain.ErrInvalidID
	}

	var fingerprintsHash []string

	if err := json.Unmarshal([]byte(m["fingerprints_hash"]), &fingerprintsHash); err != nil {
		return domain.User{}, domain.ErrInvalidFingerprintsHash
	}

	createdAt, err := time.Parse(time.RFC3339, m["created_at"])
	if err != nil {
		return domain.User{}, domain.ErrInvalidTime
	}

	updatedAt, err := time.Parse(time.RFC3339, m["updated_at"])
	if err != nil {
		return domain.User{}, domain.ErrInvalidTime
	}

	return domain.User{
		ID:               id,
		Email:            m["email"],
		PasswordHash:     m["password_hash"],
		Salt:             m["salt"],
		SecretPhrase:     m["secret_phrase"],
		SecretPhraseHint: m["secret_phrase_hint"],
		FingerprintsHash: fingerprintsHash,
		CreatedAt:        createdAt,
		UpdatedAt:        updatedAt,
	}, nil
}

func (tu *TemporaryUsers) Create(ctx context.Context, user domain.User, expiresAt time.Duration) error {
	key := fmt.Sprintf("%s:%s", tu.namespace, user.Email)

	exists, err := tu.client.Exists(ctx, []string{key})
	if err != nil {
		return err
	}

	if exists > 0 {
		return domain.ErrUserAlreadyExists
	}

	hashes, err := json.Marshal(user.FingerprintsHash)
	if err != nil {
		return domain.ErrInvalidFingerprintsHash
	}

	options := options.NewHSetExOptions().SetExpiry(options.NewExpiryIn(expiresAt))

	if _, err := tu.client.HSetEx(ctx, key, map[string]string{
		"id":                 user.ID.String(),
		"email":              user.Email,
		"password_hash":      user.PasswordHash,
		"salt":               user.Salt,
		"secret_phrase":      user.SecretPhrase,
		"secret_phrase_hint": user.SecretPhraseHint,
		"fingerprints_hash":  string(hashes),
		"created_at":         user.CreatedAt.Format(time.RFC3339),
		"updated_at":         user.UpdatedAt.Format(time.RFC3339),
	}, options); err != nil {
		return err
	}

	return nil
}

func (tu *TemporaryUsers) Delete(ctx context.Context, email string) error {
	key := fmt.Sprintf("%s:%s", tu.namespace, email)

	if _, err := tu.client.Del(ctx, []string{key}); err != nil {
		return err
	}

	return nil
}

package valkey

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/safechildhood/auth/internal/domain"
	glide "github.com/valkey-io/valkey-glide/go/v2"
	"github.com/valkey-io/valkey-glide/go/v2/options"
	"github.com/valkey-io/valkey-glide/go/v2/pipeline"
	"github.com/valkey-io/valkey-go"
)

type RefreshTokens struct {
	client *glide.Client

	namespace     string
	userNamespace string
}

func NewRefreshTokens(client *glide.Client, namespace string, userNamespace string) *RefreshTokens {
	return &RefreshTokens{
		client:        client,
		namespace:     namespace,
		userNamespace: userNamespace,
	}
}

func (rt *RefreshTokens) Get(ctx context.Context, tokenHash string) (domain.RefreshToken, error) {
	m, err := rt.client.HGetAll(ctx, fmt.Sprintf("%s:%s", rt.namespace, tokenHash))
	if err != nil {
		return domain.RefreshToken{}, err
	}
	if len(m) == 0 {
		return domain.RefreshToken{}, domain.ErrRefreshTokenNotFound
	}

	userID, err := uuid.Parse(m["user_id"])
	if err != nil {
		return domain.RefreshToken{}, domain.ErrInvalidID
	}

	expiresAt, err := time.Parse(time.RFC3339, m["expires_at"])
	if err != nil {
		return domain.RefreshToken{}, domain.ErrInvalidTime
	}

	return domain.RefreshToken{
		UserID:          userID,
		TokenHash:       tokenHash,
		FingerprintHash: m["fingerprint_hash"],
		ExpiresAt:       expiresAt,
	}, nil
}

func (rt *RefreshTokens) Create(ctx context.Context, refreshToken domain.RefreshToken) error {
	key := fmt.Sprintf("%s:%s", rt.namespace, refreshToken.TokenHash)

	exists, err := rt.client.Exists(ctx, []string{key})
	if err != nil {
		return err
	}

	if exists > 0 {
		return domain.ErrRefreshTokenAlreadyExists
	}

	userKey := fmt.Sprintf("%s:%s", rt.userNamespace, refreshToken.UserID.String())

	options := options.NewHSetExOptions().SetExpiry(options.NewExpiryIn(time.Until(refreshToken.ExpiresAt)))

	transaction := pipeline.NewStandaloneBatch(true).
		HSetEx(key, map[string]string{
			"user_id":          refreshToken.UserID.String(),
			"token_hash":       refreshToken.TokenHash,
			"fingerprint_hash": refreshToken.FingerprintHash,
			"expires_at":       refreshToken.ExpiresAt.Format(time.RFC3339),
		}, options).
		SAdd(userKey, []string{refreshToken.TokenHash})

	if _, err := rt.client.Exec(ctx, *transaction, true); err != nil {
		return err
	}

	return nil
}

func (rt *RefreshTokens) UpdateTTL(ctx context.Context, tokenHash string, expiresIn time.Duration) error {
	options := options.NewHSetExOptions().SetExpiry(options.NewExpiryIn(expiresIn))

	if _, err := rt.client.HSetEx(ctx, fmt.Sprintf("%s:%s", rt.namespace, tokenHash), map[string]string{
		"expires_at": time.Now().Add(expiresIn).Format(time.RFC3339),
	}, options); err != nil {
		return err
	}

	return nil
}

func (rt *RefreshTokens) Delete(ctx context.Context, tokenHash string) error {
	key := fmt.Sprintf("%s:%s", rt.namespace, tokenHash)

	ownerID, err := rt.client.HGet(ctx, key, "user_id")
	if err != nil {
		return err
	}

	userKey := fmt.Sprintf("%s:%s", rt.userNamespace, ownerID.Value())

	transaction := pipeline.NewStandaloneBatch(true).
		Del([]string{key}).
		SRem(userKey, []string{tokenHash})

	if _, err := rt.client.Exec(ctx, *transaction, true); err != nil {
		return err
	}

	return nil
}

func (rt *RefreshTokens) DeleteAllByUserID(ctx context.Context, userID uuid.UUID) error {
	userKey := fmt.Sprintf("%s:%s", rt.userNamespace, userID.String())

	tokensHash, err := rt.client.SMembers(ctx, userKey)
	if err != nil {
		return err
	}

	transaction := pipeline.NewStandaloneBatch(true)

	for tokenHash := range tokensHash {
		key := fmt.Sprintf("%s:%s", rt.namespace, tokenHash)

		ownerID, err := rt.client.HGet(ctx, key, "user_id")
		if err != nil && !errors.Is(err, valkey.Nil) {
			return err
		}

		if ownerID.Value() == userID.String() {
			transaction = transaction.Del([]string{key})
		}
	}

	if _, err := rt.client.Exec(ctx, *transaction.Del([]string{userKey}), true); err != nil {
		return err
	}

	return nil
}

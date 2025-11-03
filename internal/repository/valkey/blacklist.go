package valkey

import (
	"context"
	"fmt"
	"time"

	"github.com/safechildhood/auth/internal/domain"
	glide "github.com/valkey-io/valkey-glide/go/v2"
	"github.com/valkey-io/valkey-glide/go/v2/options"
)

type Blacklist struct {
	client *glide.Client

	namespace            string
	accessTokenNamespace string
}

func NewBlacklist(client *glide.Client, namespace string, accessTokenNamespace string) *Blacklist {
	return &Blacklist{
		client:               client,
		namespace:            namespace,
		accessTokenNamespace: accessTokenNamespace,
	}
}

func (b *Blacklist) Get(ctx context.Context, id string, objectType domain.BlacklistObjectType) (any, error) {
	var key string

	switch objectType {
	case domain.BlacklistAccessTokenType:
		key = fmt.Sprintf("%s:%s:%s", b.namespace, b.accessTokenNamespace, id)

	default:
		return nil, domain.ErrUnknownObjectType
	}

	m, err := b.client.HGetAll(ctx, key)
	if err != nil {
		return nil, err
	}

	if len(m) == 0 {
		return nil, domain.ErrBlacklistItemNotFound
	}

	switch objectType {
	case domain.BlacklistAccessTokenType:
		expiresAt, err := time.Parse(time.RFC3339, m["expires_at"])
		if err != nil {
			fmt.Println(m)
			return nil, domain.ErrInvalidTime
		}

		return domain.BlacklistAccessToken{
			AccessTokenHash: m["access_token_hash"],
			ExpiresAt:       expiresAt,
		}, nil

	default:
		return nil, domain.ErrUnknownObjectType
	}
}

func (b *Blacklist) Create(ctx context.Context, objectType domain.BlacklistObjectType, object any) error {
	switch objectType {
	case domain.BlacklistAccessTokenType:
		v, ok := object.(*domain.BlacklistAccessToken)
		if !ok {
			return domain.ErrParsingObject
		}

		key := fmt.Sprintf("%s:%s:%s", b.namespace, b.accessTokenNamespace, v.AccessTokenHash)

		options := options.NewHSetExOptions().SetExpiry(options.NewExpiryIn(time.Until(v.ExpiresAt)))

		if _, err := b.client.HSetEx(ctx, key, map[string]string{
			"access_token_hash": v.AccessTokenHash,
			"expires_at":        v.ExpiresAt.Format(time.RFC3339),
		}, options); err != nil {
			return err
		}

	default:
		return domain.ErrUnknownObjectType
	}

	return nil
}

func (b *Blacklist) Delete(ctx context.Context, id string, objectType domain.BlacklistObjectType) error {
	var key string

	switch objectType {
	case domain.BlacklistAccessTokenType:
		key = fmt.Sprintf("%s:%s:%s", b.namespace, b.accessTokenNamespace, id)

	default:
		return domain.ErrUnknownObjectType
	}

	if _, err := b.client.Del(ctx, []string{key}); err != nil {
		return err
	}

	return nil
}

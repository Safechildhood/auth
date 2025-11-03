package valkey

import (
	"context"
	"fmt"
	"time"

	"github.com/safechildhood/auth/internal/domain"
	glide "github.com/valkey-io/valkey-glide/go/v2"
	"github.com/valkey-io/valkey-glide/go/v2/options"
)

type VerificationCodes struct {
	client *glide.Client

	namespace     string
	userNamespace string
}

func NewVerificationCodes(client *glide.Client, namespace string, userNamespace string) *VerificationCodes {
	return &VerificationCodes{
		client:        client,
		namespace:     namespace,
		userNamespace: userNamespace,
	}
}

func (vc *VerificationCodes) Exists(ctx context.Context, email string) (bool, error) {
	exists, err := vc.client.Exists(ctx, []string{fmt.Sprintf("%s:%s", vc.userNamespace, email)})
	if err != nil {
		return false, err
	}

	return exists > 0, nil
}

func (vc *VerificationCodes) Get(ctx context.Context, email string) (domain.VerificationCode, error) {
	m, err := vc.client.HGetAll(ctx, fmt.Sprintf("%s:%s", vc.userNamespace, email))
	if err != nil {
		return domain.VerificationCode{}, err
	}

	if len(m) == 0 {
		return domain.VerificationCode{}, domain.ErrVerificationCodeNotFound
	}

	createdAt, err := time.Parse(time.RFC3339, m["created_at"])
	if err != nil {
		return domain.VerificationCode{}, domain.ErrInvalidTime
	}

	expiresAt, err := time.Parse(time.RFC3339, m["expires_at"])
	if err != nil {
		return domain.VerificationCode{}, domain.ErrInvalidTime
	}

	return domain.VerificationCode{
		Code:      m["code"],
		Email:     email,
		ExpiresAt: expiresAt,
		CreatedAt: createdAt,
	}, nil
}

func (vc *VerificationCodes) Create(ctx context.Context, verificationCode domain.VerificationCode) error {
	key := fmt.Sprintf("%s:%s", vc.userNamespace, verificationCode.Email)

	exists, err := vc.client.Exists(ctx, []string{key})
	if err != nil {
		return err
	}

	if exists > 0 {
		return domain.ErrVerificationCodeAlreadyExists
	}

	options := options.NewHSetExOptions().SetExpiry(options.NewExpiryIn(time.Until(verificationCode.ExpiresAt)))

	if _, err := vc.client.HSetEx(ctx, key, map[string]string{
		"code":       verificationCode.Code,
		"email":      verificationCode.Email,
		"created_at": verificationCode.CreatedAt.Format(time.RFC3339),
		"expires_at": verificationCode.ExpiresAt.Format(time.RFC3339),
	}, options); err != nil {
		return err
	}

	return nil
}

func (vc *VerificationCodes) Delete(ctx context.Context, email string) error {
	key := fmt.Sprintf("%s:%s", vc.userNamespace, email)

	if _, err := vc.client.Del(ctx, []string{key}); err != nil {
		return err
	}

	return nil
}

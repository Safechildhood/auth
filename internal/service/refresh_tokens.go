package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/safechildhood/auth/internal/domain"
	"github.com/safechildhood/auth/internal/repository"
	"github.com/safechildhood/auth/pkg/crypto/manager"
)

type RefreshTokensService struct {
	refreshTokens repository.RefreshTokens

	refreshTokenTTL time.Duration

	cryptoManager manager.Crypto
}

func NewRefreshTokensService(
	refreshTokens repository.RefreshTokens,
	refreshTokenTTL time.Duration,
	cryptoManager manager.Crypto,
) *RefreshTokensService {
	return &RefreshTokensService{
		refreshTokens:   refreshTokens,
		refreshTokenTTL: refreshTokenTTL,
		cryptoManager:   cryptoManager,
	}
}

func (rts *RefreshTokensService) VerifyTokenAndFingerprint(ctx context.Context, token uuid.UUID, fingerprint string, userID uuid.UUID) (bool, error) {
	tokenHash, err := rts.cryptoManager.Hash(token[:], nil)
	if err != nil {
		return false, err
	}

	refreshToken, err := rts.refreshTokens.Get(ctx, base64.StdEncoding.EncodeToString(tokenHash))
	if err != nil {
		fmt.Println(1, err)
		return false, err
	}

	fingerprintHash, err := rts.cryptoManager.Hash([]byte(fingerprint), nil)
	if err != nil {
		return false, err
	}

	if userID != refreshToken.UserID {
		return false, domain.ErrInvalidRefreshToken
	}

	if base64.StdEncoding.EncodeToString(fingerprintHash) == refreshToken.FingerprintHash {
		return false, domain.ErrInvalidFingerprintsHash
	}

	return true, nil
}

func (rts *RefreshTokensService) Get(ctx context.Context, token uuid.UUID) (domain.RefreshToken, error) {
	tokenHash, err := rts.cryptoManager.Hash(token[:], nil)
	if err != nil {
		return domain.RefreshToken{}, err
	}

	return rts.refreshTokens.Get(ctx, base64.StdEncoding.EncodeToString(tokenHash))
}

func (rts *RefreshTokensService) Create(ctx context.Context, userID uuid.UUID, fingerprint string) (uuid.UUID, error) {
	token, err := uuid.NewUUID()
	if err != nil {
		return uuid.Nil, err
	}

	tokenHash, err := rts.cryptoManager.Hash(token[:], nil)
	if err != nil {
		return uuid.Nil, err
	}

	fingerprintHash, err := rts.cryptoManager.Hash([]byte(fingerprint), nil)
	if err != nil {
		return uuid.Nil, err
	}

	if err := rts.refreshTokens.Create(ctx, domain.RefreshToken{
		UserID:          userID,
		TokenHash:       base64.StdEncoding.EncodeToString(tokenHash),
		FingerprintHash: base64.StdEncoding.EncodeToString(fingerprintHash),
		ExpiresAt:       time.Now().Add(rts.refreshTokenTTL),
	}); err != nil {
		return uuid.Nil, err
	}

	return token, nil
}

func (rts *RefreshTokensService) ExtendTokenTTL(ctx context.Context, token uuid.UUID) error {
	token, err := uuid.NewUUID()
	if err != nil {
		return err
	}

	tokenHash, err := rts.cryptoManager.Hash(token[:], nil)
	if err != nil {
		return err
	}

	return rts.refreshTokens.UpdateTTL(ctx, base64.StdEncoding.EncodeToString(tokenHash), rts.refreshTokenTTL)
}

func (rts *RefreshTokensService) Delete(ctx context.Context, token uuid.UUID) error {
	tokenHash, err := rts.cryptoManager.Hash(token[:], nil)
	if err != nil {
		return err
	}

	return rts.refreshTokens.Delete(ctx, base64.StdEncoding.EncodeToString(tokenHash))
}

func (rts *RefreshTokensService) DeleteAllByUserID(ctx context.Context, userID uuid.UUID) error {
	return rts.refreshTokens.DeleteAllByUserID(ctx, userID)
}

package service

import (
	"context"
	"encoding/base64"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/safechildhood/auth/internal/domain"
	"github.com/safechildhood/auth/internal/repository"
	"github.com/safechildhood/auth/pkg/crypto/manager"
	jwtmanager "github.com/safechildhood/auth/pkg/jwt"
)

type AccessTokensService struct {
	blacklist repository.Blacklist

	accessTokenTTL time.Duration

	tokenManager  jwtmanager.Manager
	cryptoManager manager.Crypto
}

func NewAccessTokensService(
	blacklist repository.Blacklist,
	accessTokenTTL time.Duration,
	tokenManager jwtmanager.Manager,
	cryptoManager manager.Crypto,
) *AccessTokensService {
	return &AccessTokensService{
		blacklist:      blacklist,
		accessTokenTTL: accessTokenTTL,
		tokenManager:   tokenManager,
		cryptoManager:  cryptoManager,
	}
}

func (ats *AccessTokensService) ParseToken(ctx context.Context, token string) (domain.TokenClaims, error) {
	claims, isValid, err := ats.tokenManager.ParseAndValidateToken(token)
	if err != nil {
		return domain.TokenClaims{}, err
	}

	if !isValid {
		return domain.TokenClaims{}, domain.ErrInvalidAccessToken
	}

	subject, err := claims.GetSubject()
	if err != nil {
		return domain.TokenClaims{}, domain.ErrInvalidAccessToken
	}

	issuer, err := claims.GetIssuer()
	if err != nil {
		return domain.TokenClaims{}, domain.ErrInvalidAccessToken
	}

	expiresAt, err := claims.GetExpirationTime()
	if err != nil {
		return domain.TokenClaims{}, domain.ErrInvalidAccessToken
	}

	issuedAt, err := claims.GetIssuedAt()
	if err != nil {
		return domain.TokenClaims{}, domain.ErrInvalidAccessToken
	}

	tokenClaims := domain.TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    issuer,
			ExpiresAt: expiresAt,
			IssuedAt:  issuedAt,
		},
	}

	return tokenClaims, nil
}

func (ats *AccessTokensService) VerifyToken(ctx context.Context, token string) (bool, error) {
	tokenHash, err := ats.cryptoManager.Hash([]byte(token), nil)
	if err != nil {
		return false, err
	}

	if _, err := ats.blacklist.Get(ctx, base64.StdEncoding.EncodeToString(tokenHash), domain.BlacklistAccessTokenType); err != nil {
		if errors.Is(err, domain.ErrBlacklistItemNotFound) {
			return true, nil
		}

		return false, err
	}

	return false, nil
}

func (ats *AccessTokensService) Create(userID uuid.UUID) (string, time.Duration, error) {
	claims := domain.TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			Issuer:    "auth-microservice",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ats.accessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	accessToken, err := ats.tokenManager.CreateToken(claims)
	if err != nil {
		return "", 0, err
	}

	return accessToken, ats.accessTokenTTL, nil
}

func (ats *AccessTokensService) AddToBlacklist(ctx context.Context, token string) error {
	tokenHash, err := ats.cryptoManager.Hash([]byte(token), nil)
	if err != nil {
		return err
	}

	return ats.blacklist.Create(ctx, domain.BlacklistAccessTokenType, domain.BlacklistAccessToken{
		AccessTokenHash: base64.StdEncoding.EncodeToString(tokenHash),
		ExpiresAt:       time.Now().Add(ats.accessTokenTTL),
	})
}

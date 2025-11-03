package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/safechildhood/auth/internal/domain"
)

type Users interface {
	Exists(ctx context.Context, email string) (bool, error)
	Get(ctx context.Context, id uuid.UUID) (domain.User, error)
	GetByEmail(ctx context.Context, email string) (domain.User, error)
	Create(ctx context.Context, user domain.User) error
	UpdatePassword(ctx context.Context, id uuid.UUID, newPasswordHash string) error
	UpdatePasswordByEmail(ctx context.Context, email string, newPasswordHash string) error
	ContainsFingerprint(ctx context.Context, id uuid.UUID, fingerprint string) (bool, error)
	AddFingerprint(ctx context.Context, id uuid.UUID, fingerprintHash string) error
}

type TemporaryUsers interface {
	GetByEmail(ctx context.Context, email string) (domain.User, error)
	Create(ctx context.Context, user domain.User, expiresAt time.Duration) error
	Delete(ctx context.Context, email string) error
}

type VerifcationCodes interface {
	Exists(ctx context.Context, email string) (bool, error)
	Get(ctx context.Context, email string) (domain.VerificationCode, error)
	Create(ctx context.Context, verificationCode domain.VerificationCode) error
	Delete(ctx context.Context, email string) error
}

type RefreshTokens interface {
	Get(ctx context.Context, tokenHash string) (domain.RefreshToken, error)
	Create(ctx context.Context, refreshToken domain.RefreshToken) error
	UpdateTTL(ctx context.Context, tokenHash string, expiresIn time.Duration) error
	Delete(ctx context.Context, tokenHash string) error
	DeleteAllByUserID(ctx context.Context, userID uuid.UUID) error
}

type Blacklist interface {
	Get(ctx context.Context, id string, objectType domain.BlacklistObjectType) (any, error)
	Create(ctx context.Context, objectType domain.BlacklistObjectType, object any) error
	Delete(ctx context.Context, id string, objectType domain.BlacklistObjectType) error
}

type Repository struct {
	Users            Users
	TemporaryUsers   TemporaryUsers
	VerifcationCodes VerifcationCodes
	RefreshTokens    RefreshTokens
	Blacklist        Blacklist
}

func New(
	users Users,
	temporaryUsers TemporaryUsers,
	verificationCodes VerifcationCodes,
	refreshTokens RefreshTokens,
	blacklist Blacklist,
) *Repository {
	return &Repository{
		Users:            users,
		TemporaryUsers:   temporaryUsers,
		VerifcationCodes: verificationCodes,
		RefreshTokens:    refreshTokens,
		Blacklist:        blacklist,
	}
}

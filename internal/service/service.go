package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/safechildhood/auth/internal/domain"
)

type Users interface {
	VerifyFingerprint(ctx context.Context, email, fingerprint string) (bool, error)
	VerifyTemporalyFingerprint(ctx context.Context, email, fingerprint string) (bool, error)
	VerifyPassword(ctx context.Context, id uuid.UUID, password string) (bool, error)
	VerifySecretPhrase(ctx context.Context, email, secretPhrase string) (bool, error)
	Exists(ctx context.Context, email string) (bool, error)
	Get(ctx context.Context, id uuid.UUID) (domain.User, error)
	GetByEmail(ctx context.Context, email string) (domain.User, error)
	GetTemporaryByEmail(ctx context.Context, email string) (domain.User, error)
	GetSecretPhraseHintByEmail(ctx context.Context, email string) (string, error)
	Create(ctx context.Context, user domain.User) error
	CreateTemporary(
		ctx context.Context,
		email string,
		password string,
		secretPhrase string,
		secretPhraseHint string,
		fingerprint string,
	) error
	UpdatePassword(ctx context.Context, id uuid.UUID, newPassword string) error
	UpdatePasswordByEmail(ctx context.Context, email string, newPassword string) error
	AddFingerprint(ctx context.Context, id uuid.UUID, fingerprint string) error
	DeleteTemporaryByEmail(ctx context.Context, email string) error
}

type Mail interface {
	SendMail(ctx context.Context, eventType domain.EventType, payload map[string]any) error
	Close() error
}

type VerificationCodes interface {
	VerifyCode(ctx context.Context, email string, code string) (bool, error)
	ValidateResendTime(ctx context.Context, email string) (bool, error)
	Exists(ctx context.Context, email string) (bool, error)
	Create(ctx context.Context, email string) (string, time.Duration, error)
	Delete(ctx context.Context, email string) error
}

type AccessTokens interface {
	ParseToken(ctx context.Context, token string) (domain.TokenClaims, error)
	VerifyToken(ctx context.Context, token string) (bool, error)
	Create(userID uuid.UUID) (string, time.Duration, error)
	AddToBlacklist(ctx context.Context, token string) error
}

type RefreshTokens interface {
	VerifyTokenAndFingerprint(ctx context.Context, token uuid.UUID, fingerprint string, userID uuid.UUID) (bool, error)
	Get(ctx context.Context, token uuid.UUID) (domain.RefreshToken, error)
	Create(ctx context.Context, userID uuid.UUID, fingerprint string) (uuid.UUID, error)
	ExtendTokenTTL(ctx context.Context, token uuid.UUID) error
	Delete(ctx context.Context, token uuid.UUID) error
	DeleteAllByUserID(ctx context.Context, userID uuid.UUID) error
}

type (
	RegisterInput struct {
		Email            string
		Password         string
		SecretPhrase     string
		SecretPhraseHint string
		Fingerprint      string
	}

	ResendCodeInput struct {
		Email       string
		Fingerprint string
	}

	LoginInput struct {
		Email       string
		Password    string
		Fingerprint string
	}

	LoginOutput struct {
		Tokens              TokensOutput
		VerificationCodeTTL time.Duration
	}

	ChangePasswordInput struct {
		Email        string
		SecretPhrase string
	}

	ChangePasswordConfirmInput struct {
		Email            string
		NewPassword      string
		VerificationCode string
	}

	ChangePasswordWithTokensInput struct {
		AccessToken    string
		RefreshToken   string
		Fingerprint    string
		OldPassword    string
		NewPassword    string
		WantsLogoutAll bool
	}

	ConfirmInput struct {
		Email            string
		VerificationCode string
		Fingerprint      string
	}

	UserSecureInput struct {
		AccessToken  string
		RefreshToken string
		Fingerprint  string
	}

	TokensOutput struct {
		AccessToken    string
		AccessTokenTTL time.Duration
		RefreshToken   string
	}
)

type Auth interface {
	Register(ctx context.Context, input RegisterInput) (verificationCodeTTL time.Duration, err error)
	RegisterConfirm(ctx context.Context, input ConfirmInput) (TokensOutput, error)

	ResendCode(ctx context.Context, input ResendCodeInput) (verificationCodeTTL time.Duration, err error)

	ValidateAction(ctx context.Context, input UserSecureInput) (bool, error)
	UpdateTokens(ctx context.Context, input UserSecureInput) (TokensOutput, error)

	Login(ctx context.Context, input LoginInput) (LoginOutput, error)
	LoginConfirm(ctx context.Context, input ConfirmInput) (TokensOutput, error)
	Logout(ctx context.Context, input UserSecureInput) (bool, error)
	LogoutAll(ctx context.Context, input UserSecureInput) (bool, error)

	GetSecretPhraseHint(ctx context.Context, email string) (string, error)

	ChangePassword(ctx context.Context, input ChangePasswordInput) (verificationCodeTTL time.Duration, err error)
	ChangePasswordConfirm(ctx context.Context, input ChangePasswordConfirmInput) (bool, error)
	ChangePasswordWithTokens(ctx context.Context, input ChangePasswordWithTokensInput) (bool, error)
}

type Service struct {
	Auth Auth
}

func New(auth Auth) *Service {
	return &Service{
		Auth: auth,
	}
}

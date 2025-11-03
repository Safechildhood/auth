package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/mirrorblade/crypto"
	"github.com/safechildhood/auth/internal/domain"
	"github.com/safechildhood/auth/internal/repository"
)

type UsersService struct {
	users          repository.Users
	temporaryUsers repository.TemporaryUsers

	temporaryUserTTL time.Duration

	saltLength int

	cryptoProvider crypto.Provider
}

func NewUsersService(
	users repository.Users,
	temporaryUsers repository.TemporaryUsers,
	temporaryUserTTL time.Duration,
	saltLength int,
	cryptoProvider crypto.Provider,
) *UsersService {
	return &UsersService{
		users:            users,
		temporaryUsers:   temporaryUsers,
		temporaryUserTTL: temporaryUserTTL,
		saltLength:       saltLength,
		cryptoProvider:   cryptoProvider,
	}
}

func (us *UsersService) VerifyFingerprint(ctx context.Context, email, fingerprint string) (bool, error) {
	user, err := us.users.GetByEmail(ctx, email)
	if err != nil {
		return false, err
	}

	fingerprintHash, err := us.cryptoProvider.Hash([]byte(fingerprint), nil)
	if err != nil {
		return false, err
	}

	return slices.Contains(user.FingerprintsHash, base64.StdEncoding.EncodeToString(fingerprintHash)), nil
}

func (us *UsersService) VerifyTemporalyFingerprint(ctx context.Context, email, fingerprint string) (bool, error) {
	user, err := us.temporaryUsers.GetByEmail(ctx, email)
	if err != nil {
		return false, err
	}

	fingerprintHash, err := us.cryptoProvider.Hash([]byte(fingerprint), nil)
	if err != nil {
		return false, err
	}

	return string(user.FingerprintsHash[0]) == base64.StdEncoding.EncodeToString(fingerprintHash), nil
}

func (us *UsersService) VerifyPassword(ctx context.Context, id uuid.UUID, password string) (bool, error) {
	user, err := us.users.Get(ctx, id)
	if err != nil {
		return false, err
	}

	salt, err := base64.StdEncoding.DecodeString(user.Salt)
	if err != nil {
		return false, err
	}

	expectedHash, err := base64.StdEncoding.DecodeString(user.PasswordHash)
	if err != nil {
		return false, err
	}

	return us.cryptoProvider.VerifyHash([]byte(password), salt, expectedHash)
}

func (us *UsersService) VerifySecretPhrase(ctx context.Context, email, secretPhrase string) (bool, error) {
	user, err := us.users.GetByEmail(ctx, email)
	if err != nil {
		return false, err
	}

	return secretPhrase == user.SecretPhrase, nil
}

func (us *UsersService) Exists(ctx context.Context, email string) (bool, error) {
	return us.users.Exists(ctx, email)
}

func (us *UsersService) Get(ctx context.Context, id uuid.UUID) (domain.User, error) {
	return us.users.Get(ctx, id)
}

func (us *UsersService) GetByEmail(ctx context.Context, email string) (domain.User, error) {
	return us.users.GetByEmail(ctx, email)
}

func (us *UsersService) GetTemporaryByEmail(ctx context.Context, email string) (domain.User, error) {
	return us.temporaryUsers.GetByEmail(ctx, email)
}

func (us *UsersService) GetSecretPhraseHintByEmail(ctx context.Context, email string) (string, error) {
	user, err := us.temporaryUsers.GetByEmail(ctx, email)
	if err != nil {
		return "", err
	}

	return user.SecretPhraseHint, nil
}

func (us *UsersService) Create(ctx context.Context, user domain.User) error {
	return us.users.Create(ctx, user)
}

func (us *UsersService) CreateTemporary(
	ctx context.Context,
	email string,
	password string,
	secretPhrase string,
	secretPhraseHint string,
	fingerprint string,
) error {
	id, err := uuid.NewUUID()
	if err != nil {
		return err
	}

	salt, err := generateSalt(us.saltLength)
	if err != nil {
		return err
	}

	passwordHash, err := us.cryptoProvider.Hash([]byte(password), salt)
	if err != nil {
		return err
	}

	fingerprintHash, err := us.cryptoProvider.Hash([]byte(fingerprint), nil)
	if err != nil {
		return err
	}

	user := domain.User{
		ID:               id,
		Email:            email,
		PasswordHash:     base64.StdEncoding.EncodeToString(passwordHash),
		Salt:             base64.StdEncoding.EncodeToString(salt),
		SecretPhrase:     secretPhrase,
		SecretPhraseHint: secretPhraseHint,
		FingerprintsHash: []string{base64.StdEncoding.EncodeToString(fingerprintHash)},
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	return us.temporaryUsers.Create(ctx, user, us.temporaryUserTTL)
}

func (us *UsersService) UpdatePassword(ctx context.Context, id uuid.UUID, newPassword string) error {
	user, err := us.users.Get(ctx, id)
	if err != nil {
		return err
	}

	passwordHash, err := us.cryptoProvider.Hash([]byte(newPassword), []byte(user.Salt))
	if err != nil {
		return err
	}

	return us.users.UpdatePassword(ctx, id, base64.StdEncoding.EncodeToString(passwordHash))
}

func (us *UsersService) UpdatePasswordByEmail(ctx context.Context, email string, newPassword string) error {
	user, err := us.users.GetByEmail(ctx, email)
	if err != nil {
		return err
	}

	passwordHash, err := us.cryptoProvider.Hash([]byte(newPassword), []byte(user.Salt))
	if err != nil {
		return err
	}

	return us.users.UpdatePasswordByEmail(ctx, email, base64.StdEncoding.EncodeToString(passwordHash))
}

func (us *UsersService) AddFingerprint(ctx context.Context, id uuid.UUID, fingerprint string) error {
	fingerprintHash, err := us.cryptoProvider.Hash([]byte(fingerprint), nil)
	if err != nil {
		return err
	}

	return us.users.AddFingerprint(ctx, id, base64.StdEncoding.EncodeToString(fingerprintHash))
}

func (us *UsersService) DeleteTemporaryByEmail(ctx context.Context, email string) error {
	return us.temporaryUsers.Delete(ctx, email)
}

func generateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)

	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}

	return salt, nil
}

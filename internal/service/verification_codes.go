package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/safechildhood/auth/internal/domain"
	"github.com/safechildhood/auth/internal/repository"
)

type VerificationCodesService struct {
	verificationCodes repository.VerifcationCodes

	verificationCodeTTL time.Duration
	resendTimeTTL       time.Duration

	codeLength int
}

func NewVerificationCodesService(
	verificationCodes repository.VerifcationCodes,
	verificationCodeTTL time.Duration,
	resendTimeTTL time.Duration,
	codeLength int,
) *VerificationCodesService {
	return &VerificationCodesService{
		verificationCodes:   verificationCodes,
		verificationCodeTTL: verificationCodeTTL,
		resendTimeTTL:       resendTimeTTL,
		codeLength:          codeLength,
	}
}

func (vcs *VerificationCodesService) VerifyCode(ctx context.Context, email string, code string) (bool, error) {
	verificationCode, err := vcs.verificationCodes.Get(ctx, email)
	if err != nil {
		return false, err
	}

	return verificationCode.Code == code, nil
}

func (vcs *VerificationCodesService) ValidateResendTime(ctx context.Context, email string) (bool, error) {
	verificationCode, err := vcs.verificationCodes.Get(ctx, email)
	if err != nil && !errors.Is(err, domain.ErrVerificationCodeNotFound) {
		return false, err
	}

	if time.Now().After(verificationCode.CreatedAt.Add(vcs.resendTimeTTL)) {
		return true, nil
	}

	return false, domain.ErrVerificationCodeResendTimeout
}

func (vcs *VerificationCodesService) Exists(ctx context.Context, email string) (bool, error) {
	return vcs.verificationCodes.Exists(ctx, email)
}

func (vcs *VerificationCodesService) Create(ctx context.Context, email string) (string, time.Duration, error) {
	code, err := generateCode(vcs.codeLength)
	if err != nil {
		return "", 0, domain.ErrGeneratingCode
	}

	if err := vcs.verificationCodes.Create(ctx, domain.VerificationCode{
		Code:      code,
		Email:     email,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(vcs.verificationCodeTTL),
	}); err != nil {
		return "", 0, err
	}

	return code, vcs.verificationCodeTTL, nil
}

func (vcs *VerificationCodesService) Delete(ctx context.Context, email string) error {
	return vcs.verificationCodes.Delete(ctx, email)
}

func generateCode(length int) (string, error) {
	maxInt := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(length)), nil)

	numCode, err := rand.Int(rand.Reader, maxInt)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%0*d", length, numCode), nil
}

package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/safechildhood/auth/internal/domain"
)

type AuthService struct {
	users             Users
	mail              Mail
	verificationCodes VerificationCodes
	accessTokens      AccessTokens
	refreshTokens     RefreshTokens
}

func NewAuthService(
	users Users,
	mail Mail,
	verificationCodes VerificationCodes,
	accessTokens AccessTokens,
	refreshTokens RefreshTokens,
) *AuthService {
	return &AuthService{
		users:             users,
		mail:              mail,
		verificationCodes: verificationCodes,
		accessTokens:      accessTokens,
		refreshTokens:     refreshTokens,
	}
}

func (as *AuthService) Register(ctx context.Context, input RegisterInput) (verificationCodeTTL time.Duration, err error) {
	if err := as.users.CreateTemporary(
		ctx,
		input.Email,
		input.Password,
		input.SecretPhrase,
		input.SecretPhraseHint,
		input.Fingerprint,
	); err != nil {
		return 0, err
	}

	code, codeTTL, err := as.verificationCodes.Create(ctx, input.Email)
	if err != nil {
		return 0, err
	}

	if err := as.mail.SendMail(ctx, domain.UserResetPasswordEvent, map[string]any{
		"code": code,
	}); err != nil {
		return 0, err
	}

	return codeTTL, nil
}

func (as *AuthService) RegisterConfirm(ctx context.Context, input ConfirmInput) (TokensOutput, error) {
	isVerified, err := as.users.VerifyTemporalyFingerprint(ctx, input.Email, input.Fingerprint)
	if err != nil {
		return TokensOutput{}, err
	}

	if !isVerified {
		return TokensOutput{}, domain.ErrFingerprintNotFound
	}

	isVerified, err = as.verificationCodes.VerifyCode(ctx, input.Email, input.VerificationCode)
	if err != nil {
		return TokensOutput{}, err
	}

	if !isVerified {
		return TokensOutput{}, domain.ErrVerificationCodeNotFound
	}

	user, err := as.users.GetTemporaryByEmail(ctx, input.Email)
	if err != nil {
		return TokensOutput{}, err
	}

	if err := as.users.DeleteTemporaryByEmail(ctx, input.Email); err != nil {
		return TokensOutput{}, err
	}

	if err := as.users.Create(ctx, user); err != nil {
		return TokensOutput{}, err
	}

	accessToken, accessTokenTTL, err := as.accessTokens.Create(user.ID)
	if err != nil {
		return TokensOutput{}, err
	}

	refreshToken, err := as.refreshTokens.Create(ctx, user.ID, user.FingerprintsHash[0])
	if err != nil {
		return TokensOutput{}, err
	}

	return TokensOutput{
		AccessToken:    accessToken,
		AccessTokenTTL: accessTokenTTL,
		RefreshToken:   refreshToken.String(),
	}, nil
}

func (as *AuthService) ResendCode(ctx context.Context, input ResendCodeInput) (verificationCodeTTL time.Duration, err error) {
	isVerified, err := as.users.VerifyFingerprint(ctx, input.Email, input.Fingerprint)
	if err != nil {
		return 0, err
	}

	if !isVerified {
		return 0, domain.ErrFingerprintNotFound
	}

	isValid, err := as.verificationCodes.ValidateResendTime(ctx, input.Email)
	if err != nil {
		return 0, err
	}

	if !isValid {
		return 0, domain.ErrVerificationCodeResendTimeout
	}

	if err := as.verificationCodes.Delete(ctx, input.Email); err != nil {
		return 0, err
	}

	code, codeTTL, err := as.verificationCodes.Create(ctx, input.Email)
	if err != nil {
		return 0, err
	}

	if err := as.mail.SendMail(ctx, domain.UserResetPasswordEvent, map[string]any{
		"code": code,
	}); err != nil {
		return 0, err
	}

	return codeTTL, nil
}

func (as *AuthService) ValidateAction(ctx context.Context, input UserSecureInput) (bool, error) {
	isVerified, err := as.accessTokens.VerifyToken(ctx, input.AccessToken)
	if err != nil {
		return false, err
	}

	if !isVerified {
		return false, domain.ErrInvalidAccessToken
	}

	accessToken, err := as.accessTokens.ParseToken(ctx, input.AccessToken)
	if err != nil {
		return false, err
	}

	refreshToken, err := uuid.Parse(input.RefreshToken)
	if err != nil {
		return false, domain.ErrInvalidRefreshToken
	}

	userID, err := uuid.Parse(accessToken.Subject)
	if err != nil {
		return false, domain.ErrInvalidID
	}

	isVerified, err = as.refreshTokens.VerifyTokenAndFingerprint(ctx, refreshToken, input.Fingerprint, userID)
	if err != nil {
		return false, err
	}

	if !isVerified {
		return false, domain.ErrInvalidAction
	}

	return true, nil
}

func (as *AuthService) UpdateTokens(ctx context.Context, input UserSecureInput) (TokensOutput, error) {
	isValid, err := as.ValidateAction(ctx, input)
	if err != nil {
		return TokensOutput{}, err
	}

	if !isValid {
		return TokensOutput{}, domain.ErrInvalidAction
	}

	refreshToken, err := uuid.Parse(input.RefreshToken)
	if err != nil {
		return TokensOutput{}, domain.ErrInvalidRefreshToken
	}

	if err := as.refreshTokens.ExtendTokenTTL(ctx, refreshToken); err != nil {
		return TokensOutput{}, err
	}

	claims, err := as.accessTokens.ParseToken(ctx, input.AccessToken)
	if err != nil {
		return TokensOutput{}, err
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return TokensOutput{}, domain.ErrInvalidID
	}

	accessToken, accessTokenTTL, err := as.accessTokens.Create(userID)
	if err != nil {
		return TokensOutput{}, err
	}

	return TokensOutput{
		AccessToken:    accessToken,
		AccessTokenTTL: accessTokenTTL,
		RefreshToken:   input.RefreshToken,
	}, nil
}

func (as *AuthService) Login(ctx context.Context, input LoginInput) (LoginOutput, error) {
	user, err := as.users.GetByEmail(ctx, input.Email)
	if err != nil {
		return LoginOutput{}, err
	}

	isVerified, err := as.users.VerifyPassword(ctx, user.ID, input.Password)
	if err != nil {
		return LoginOutput{}, err
	}

	if !isVerified {
		return LoginOutput{}, domain.ErrInvalidPassword
	}

	isVerified, err = as.users.VerifyFingerprint(ctx, input.Email, input.Fingerprint)
	if err != nil {
		return LoginOutput{}, err
	}

	output := LoginOutput{}

	if isVerified {
		accessToken, accessTokenTTL, err := as.accessTokens.Create(user.ID)
		if err != nil {
			return LoginOutput{}, err
		}

		refreshToken, err := as.refreshTokens.Create(ctx, user.ID, input.Fingerprint)
		if err != nil {
			return LoginOutput{}, err
		}

		output.Tokens = TokensOutput{
			AccessToken:    accessToken,
			AccessTokenTTL: accessTokenTTL,
			RefreshToken:   refreshToken.String(),
		}

	} else {
		code, codeTTL, err := as.verificationCodes.Create(ctx, input.Email)
		if err != nil {
			return LoginOutput{}, err
		}

		if err := as.mail.SendMail(ctx, domain.UserResetPasswordEvent, map[string]any{
			"code": code,
		}); err != nil {
			return LoginOutput{}, err
		}

		output.VerificationCodeTTL = codeTTL
	}

	return output, nil
}

func (as *AuthService) LoginConfirm(ctx context.Context, input ConfirmInput) (output TokensOutput, err error) {
	isVerified, err := as.verificationCodes.VerifyCode(ctx, input.Email, input.VerificationCode)
	if err != nil {
		return TokensOutput{}, err
	}

	if !isVerified {
		return TokensOutput{}, domain.ErrInvalidVerificationCode
	}

	defer func() {
		if e := as.verificationCodes.Delete(ctx, input.Email); e != nil {
			err = e
		}
	}()

	user, err := as.users.GetByEmail(ctx, input.Email)
	if err != nil {
		return TokensOutput{}, err
	}

	if err := as.users.AddFingerprint(ctx, user.ID, input.Fingerprint); err != nil {
		return TokensOutput{}, err
	}

	accessToken, accessTokenTTL, err := as.accessTokens.Create(user.ID)
	if err != nil {
		return TokensOutput{}, err
	}

	refreshToken, err := as.refreshTokens.Create(ctx, user.ID, input.Fingerprint)
	if err != nil {
		return TokensOutput{}, err
	}

	return TokensOutput{
		AccessToken:    accessToken,
		AccessTokenTTL: accessTokenTTL,
		RefreshToken:   refreshToken.String(),
	}, nil
}

func (as *AuthService) Logout(ctx context.Context, input UserSecureInput) (bool, error) {
	isValid, err := as.ValidateAction(ctx, input)
	if err != nil {
		return false, err
	}

	if !isValid {
		return false, domain.ErrInvalidAction
	}

	refreshToken, err := uuid.Parse(input.RefreshToken)
	if err != nil {
		return false, domain.ErrInvalidRefreshToken
	}

	if err := as.refreshTokens.Delete(ctx, refreshToken); err != nil {
		return false, err
	}

	if err := as.accessTokens.AddToBlacklist(ctx, input.AccessToken); err != nil {
		return false, err
	}

	return true, nil
}

func (as *AuthService) LogoutAll(ctx context.Context, input UserSecureInput) (bool, error) {
	isValid, err := as.ValidateAction(ctx, input)
	if err != nil {
		return false, err
	}

	if !isValid {
		return false, domain.ErrInvalidAction
	}

	claims, err := as.accessTokens.ParseToken(ctx, input.AccessToken)
	if err != nil {
		return false, err
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return false, domain.ErrInvalidID
	}

	if err := as.refreshTokens.DeleteAllByUserID(ctx, userID); err != nil {
		return false, err
	}

	return true, nil
}

func (as *AuthService) GetSecretPhraseHint(ctx context.Context, email string) (string, error) {
	exists, err := as.verificationCodes.Exists(ctx, email)
	if err != nil {
		return "", err
	}

	if !exists {
		return "", domain.ErrVerificationCodeNotFound
	}

	user, err := as.users.GetByEmail(ctx, email)
	if err != nil {
		return "", err
	}

	return user.SecretPhraseHint, nil
}

func (as *AuthService) ChangePassword(ctx context.Context, input ChangePasswordInput) (verificationCodeTTL time.Duration, err error) {
	exists, err := as.users.Exists(ctx, input.Email)
	if err != nil {
		return 0, err
	}

	if !exists {
		return 0, domain.ErrUserNotFound
	}

	isVerified, err := as.users.VerifySecretPhrase(ctx, input.Email, input.SecretPhrase)
	if err != nil {
		return 0, err
	}

	if !isVerified {
		return 0, domain.ErrInvalidSecretPhrase
	}

	code, codeTTL, err := as.verificationCodes.Create(ctx, input.Email)
	if err != nil {
		return 0, err
	}

	if err := as.mail.SendMail(ctx, domain.UserResetPasswordEvent, map[string]any{
		"code": code,
	}); err != nil {
		return 0, err
	}

	return codeTTL, err
}

func (as *AuthService) ChangePasswordConfirm(ctx context.Context, input ChangePasswordConfirmInput) (success bool, err error) {
	exists, err := as.users.Exists(ctx, input.Email)
	if err != nil {
		return false, err
	}

	if !exists {
		return false, domain.ErrUserNotFound
	}

	isVerified, err := as.verificationCodes.VerifyCode(ctx, input.Email, input.VerificationCode)
	if err != nil {
		return false, err
	}

	if !isVerified {
		return false, domain.ErrInvalidVerificationCode
	}

	defer func() {
		if e := as.verificationCodes.Delete(ctx, input.Email); e != nil {
			err = e
		}
	}()

	if err := as.users.UpdatePasswordByEmail(ctx, input.Email, input.NewPassword); err != nil {
		return false, err
	}

	return true, nil
}

func (as *AuthService) ChangePasswordWithTokens(ctx context.Context, input ChangePasswordWithTokensInput) (bool, error) {
	isValid, err := as.ValidateAction(ctx, UserSecureInput{
		AccessToken:  input.AccessToken,
		RefreshToken: input.RefreshToken,
		Fingerprint:  input.Fingerprint,
	})
	if err != nil {
		return false, err
	}

	if !isValid {
		return false, domain.ErrInvalidAction
	}

	claims, err := as.accessTokens.ParseToken(ctx, input.AccessToken)
	if err != nil {
		return false, domain.ErrInvalidAccessToken
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return false, domain.ErrInvalidID
	}

	isVerified, err := as.users.VerifyPassword(ctx, userID, input.OldPassword)
	if err != nil {
		return false, err
	}

	if !isVerified {
		return false, domain.ErrInvalidPassword
	}

	if err := as.users.UpdatePassword(ctx, userID, input.NewPassword); err != nil {
		return false, err
	}

	if input.WantsLogoutAll {
		if err := as.refreshTokens.DeleteAllByUserID(ctx, userID); err != nil {
			return false, err
		}
	}

	return true, nil
}

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

// TODO: Return code ttl (+)
func (as *AuthService) Register(ctx context.Context, input RegisterInput) (verificationCodeTTL time.Duration, err error) {
	// TODO: Create user (with fingerprint) in temporaly db

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

	// TODO: Add code to temp db (+)

	code, codeTTL, err := as.verificationCodes.Create(ctx, input.Email)
	if err != nil {
		return 0, err
	}

	// TODO: Send code in email (RabbitMq)

	if err := as.mail.SendMail(ctx, domain.UserResetPasswordEvent, map[string]any{
		"code": code,
	}); err != nil {
		return 0, err
	}

	// TODO: Return code ttl

	return codeTTL, nil
}

// TODO: Return tokens, ttl of access token and errors (+)
func (as *AuthService) RegisterConfirm(ctx context.Context, input ConfirmInput) (TokensOutput, error) {
	// TODO: Validate fingerprint

	isVerified, err := as.users.VerifyTemporalyFingerprint(ctx, input.Email, input.Fingerprint)
	if err != nil {
		return TokensOutput{}, err
	}

	if !isVerified {
		return TokensOutput{}, domain.ErrFingerprintNotFound
	}

	// TODO: Validate code (+)

	isVerified, err = as.verificationCodes.VerifyCode(ctx, input.Email, input.VerificationCode)
	if err != nil {
		return TokensOutput{}, err
	}

	if !isVerified {
		return TokensOutput{}, domain.ErrVerificationCodeNotFound
	}

	// TODO: Create user in main db (+)

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

	// TODO: Create access and refresh tokens

	accessToken, accessTokenTTL, err := as.accessTokens.Create(user.ID)
	if err != nil {
		return TokensOutput{}, err
	}

	refreshToken, err := as.refreshTokens.Create(ctx, user.ID, user.FingerprintsHash[0])
	if err != nil {
		return TokensOutput{}, err
	}

	// TODO: Return it
	return TokensOutput{
		AccessToken:    accessToken,
		AccessTokenTTL: accessTokenTTL,
		RefreshToken:   refreshToken.String(),
	}, nil
}

// TODO: Receive verification code (+)
func (as *AuthService) ResendCode(ctx context.Context, input ResendCodeInput) (verificationCodeTTL time.Duration, err error) {
	// TODO: Valiate fingerprint

	isVerified, err := as.users.VerifyFingerprint(ctx, input.Email, input.Fingerprint)
	if err != nil {
		return 0, err
	}

	if !isVerified {
		return 0, domain.ErrFingerprintNotFound
	}

	// TODO: Validate time of code

	isValid, err := as.verificationCodes.ValidateResendTime(ctx, input.Email)
	if err != nil {
		return 0, err
	}

	if !isValid {
		return 0, domain.ErrVerificationCodeResendTimeout
	}

	// TODO: Delete old code

	if err := as.verificationCodes.Delete(ctx, input.Email); err != nil {
		return 0, err
	}

	// TODO: Create new one

	code, codeTTL, err := as.verificationCodes.Create(ctx, input.Email)
	if err != nil {
		return 0, err
	}

	if err := as.mail.SendMail(ctx, domain.UserResetPasswordEvent, map[string]any{
		"code": code,
	}); err != nil {
		return 0, err
	}

	// TODO: Return ttl of new one

	return codeTTL, nil
}

// TODO: Receive user's tokens (+)
func (as *AuthService) ValidateAction(ctx context.Context, input UserSecureInput) (bool, error) {
	// TODO: Verify access token

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

	// TODO: Validate fingerprint
	// TODO: Check if session exists

	isVerified, err = as.refreshTokens.VerifyTokenAndFingerprint(ctx, refreshToken, input.Fingerprint, userID)
	if err != nil {
		return false, err
	}

	if !isVerified {
		return false, domain.ErrInvalidAction
	}

	return true, nil
}

// TODO: Receive user's tokens and return new tokens (+)
func (as *AuthService) UpdateTokens(ctx context.Context, input UserSecureInput) (TokensOutput, error) {
	// TODO: VerifyAction()

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

	// TODO: Extend refreshToken ttl

	if err := as.refreshTokens.ExtendTokenTTL(ctx, refreshToken); err != nil {
		return TokensOutput{}, err
	}

	// TODO: Generate new access token

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

	// TODO: Return new tokens

	return TokensOutput{
		AccessToken:    accessToken,
		AccessTokenTTL: accessTokenTTL,
		RefreshToken:   input.RefreshToken,
	}, nil
}

// TODO: Return tokens, (ttl of access token or verification code ttl) and errors (+)
func (as *AuthService) Login(ctx context.Context, input LoginInput) (LoginOutput, error) {
	// TODO: Check if user exists and password is valid

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

	// TODO: If fingerprint exists, then create tokens, else send mail with code

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

	// TODO: Return it

	return output, nil
}

// TODO: Return tokens, ttl of access token and errors (+)
func (as *AuthService) LoginConfirm(ctx context.Context, input ConfirmInput) (output TokensOutput, err error) {
	// TODO: Validate code
	// TODO: Delete code if its valid (could be defer call)

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

	// TODO: Add new fingerprint to user's in main db

	if err := as.users.AddFingerprint(ctx, user.ID, input.Fingerprint); err != nil {
		return TokensOutput{}, err
	}

	// TODO: Create access and refresh tokens

	accessToken, accessTokenTTL, err := as.accessTokens.Create(user.ID)
	if err != nil {
		return TokensOutput{}, err
	}

	refreshToken, err := as.refreshTokens.Create(ctx, user.ID, input.Fingerprint)
	if err != nil {
		return TokensOutput{}, err
	}

	// TODO: Return it

	return TokensOutput{
		AccessToken:    accessToken,
		AccessTokenTTL: accessTokenTTL,
		RefreshToken:   refreshToken.String(),
	}, nil
}

// TODO: Receive user's tokens and fingerprint (+)
func (as *AuthService) Logout(ctx context.Context, input UserSecureInput) (bool, error) {
	// TODO: VerifyAction()

	isValid, err := as.ValidateAction(ctx, input)
	if err != nil {
		return false, err
	}

	if !isValid {
		return false, domain.ErrInvalidAction
	}

	// TODO: Delete refresh token from main db

	refreshToken, err := uuid.Parse(input.RefreshToken)
	if err != nil {
		return false, domain.ErrInvalidRefreshToken
	}

	if err := as.refreshTokens.Delete(ctx, refreshToken); err != nil {
		return false, err
	}

	// TODO: Add access token to blacklist

	if err := as.accessTokens.AddToBlacklist(ctx, input.AccessToken); err != nil {
		return false, err
	}

	return true, nil
}

// TODO: Receive user's tokens and fingerprint (+)
func (as *AuthService) LogoutAll(ctx context.Context, input UserSecureInput) (bool, error) {
	// TODO: VerifyAction()

	isValid, err := as.ValidateAction(ctx, input)
	if err != nil {
		return false, err
	}

	if !isValid {
		return false, domain.ErrInvalidAction
	}

	// TODO: Delete all sessions

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

// TODO: (+)
func (as *AuthService) GetSecretPhraseHint(ctx context.Context, email string) (string, error) {
	// TODO: Check if some verifiction code in user's store

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

	// TODO: Return secret phrase hint

	return user.SecretPhraseHint, nil
}

// TODO: Receive email and secret phrase (+)
func (as *AuthService) ChangePassword(ctx context.Context, input ChangePasswordInput) (verificationCodeTTL time.Duration, err error) {
	// TODO: Check if user exists

	exists, err := as.users.Exists(ctx, input.Email)
	if err != nil {
		return 0, err
	}

	if !exists {
		return 0, domain.ErrUserNotFound
	}

	// TODO: Enter and validate secret phrase (soon)

	isVerified, err := as.users.VerifySecretPhrase(ctx, input.Email, input.SecretPhrase)
	if err != nil {
		return 0, err
	}

	if !isVerified {
		return 0, domain.ErrInvalidSecretPhrase
	}

	// TODO: Send code on email

	code, codeTTL, err := as.verificationCodes.Create(ctx, input.Email)
	if err != nil {
		return 0, err
	}

	if err := as.mail.SendMail(ctx, domain.UserResetPasswordEvent, map[string]any{
		"code": code,
	}); err != nil {
		return 0, err
	}

	// TODO: Return code ttl

	return codeTTL, err
}

// TODO: Receive email, code and new password (+)
func (as *AuthService) ChangePasswordConfirm(ctx context.Context, input ChangePasswordConfirmInput) (success bool, err error) {
	// TODO: Check if user exists

	exists, err := as.users.Exists(ctx, input.Email)
	if err != nil {
		return false, err
	}

	if !exists {
		return false, domain.ErrUserNotFound
	}

	// TODO: Check if code is valid
	// TODO: Delete code

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

	// TODO: Change password

	if err := as.users.UpdatePasswordByEmail(ctx, input.Email, input.NewPassword); err != nil {
		return false, err
	}

	return true, nil
}

// TODO: Receive tokens, old and new password, and isLogout (+)
func (as *AuthService) ChangePasswordWithTokens(ctx context.Context, input ChangePasswordWithTokensInput) (bool, error) {
	// TODO: VerifyAction()

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

	//

	claims, err := as.accessTokens.ParseToken(ctx, input.AccessToken)
	if err != nil {
		return false, domain.ErrInvalidAccessToken
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return false, domain.ErrInvalidID
	}

	// TODO: Check if old password matches

	isVerified, err := as.users.VerifyPassword(ctx, userID, input.OldPassword)
	if err != nil {
		return false, err
	}

	if !isVerified {
		return false, domain.ErrInvalidPassword
	}

	// TODO: Change password

	if err := as.users.UpdatePassword(ctx, userID, input.NewPassword); err != nil {
		return false, err
	}

	// TODO: If user wants, then LogoutAll

	if input.WantsLogoutAll {
		if err := as.refreshTokens.DeleteAllByUserID(ctx, userID); err != nil {
			return false, err
		}
	}

	return true, nil
}

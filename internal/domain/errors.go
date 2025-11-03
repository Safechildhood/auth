package domain

import "errors"

var (
	ErrInvalidID     = errors.New("id is not valid")
	ErrInvalidTime   = errors.New("time is not valid")
	ErrInvalidAction = errors.New("action is not valid")

	ErrInvalidFingerprintsHash = errors.New("fingerprints hash are not valid")
	ErrFingerprintNotFound     = errors.New("fingerprint is not found")

	ErrUserNotFound      = errors.New("user is not found")
	ErrUserAlreadyExists = errors.New("user already exists")

	ErrInvalidPassword     = errors.New("password is not valid")
	ErrInvalidSecretPhrase = errors.New("secret phrase is not valid")

	ErrGeneratingCode                = errors.New("generating code was failed")
	ErrVerificationCodeResendTimeout = errors.New("verification code resend timeout has not expired yet")
	ErrInvalidVerificationCode       = errors.New("verification code is not valid")
	ErrVerificationCodeNotFound      = errors.New("verification code is not found")
	ErrVerificationCodeAlreadyExists = errors.New("verification code already exists")

	ErrInvalidAccessToken = errors.New("access token is not valid")

	ErrInvalidRefreshToken       = errors.New("refresh token is not valid")
	ErrRefreshTokenNotFound      = errors.New("refresh token is not found")
	ErrRefreshTokenAlreadyExists = errors.New("refresh token already exists")

	ErrBlacklistItemNotFound = errors.New("blacklist item is not found")

	ErrUnknownObjectType = errors.New("unkown object type")
	ErrParsingObject     = errors.New("parsing object was failed")
	ErrParsingObjectType = errors.New("parsing object type was failed")

	ErrUnknownEventType = errors.New("unknown event type")
)

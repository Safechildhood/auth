package jwt

import "errors"

var (
	ErrNoKeysProvided          = errors.New("no keys are invalid")
	ErrUnexpectedSigningMethod = errors.New("unexpected signing method")
	ErrFailedClaimsParsing     = errors.New("parsing claims was failed")
)

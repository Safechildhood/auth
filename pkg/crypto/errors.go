package crypto

import "errors"

var (
	ErrUnknownAlgorithmType = errors.New("unknown algorithm type")
	ErrUnknownKeySize       = errors.New("unknown key size")
	ErrFailedKeyGeneration  = errors.New("key generation was failed")

	ErrNoManagerProvided           = errors.New("no manager is provided")
	ErrNoCallbackFunctionsProvided = errors.New("no callback functions are provided")

	ErrFailedPEMBlockParsing = errors.New("PEM block parsing was failed")
	ErrInvalidPEMBlock       = errors.New("PEM block is invalid")
	ErrInvalidPKIXKey        = errors.New("PKIX key is invalid")
	ErrInvalidPrivateKey     = errors.New("private key is invalid")
	ErrInvalidPublicKey      = errors.New("public key is invalid")

	ErrCipherTextInvalidLength = errors.New("cipher text has invalid length")

	ErrArgon2SaltLengthShort = errors.New("argon2 salt length is short")
)

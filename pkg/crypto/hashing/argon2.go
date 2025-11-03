package hashing

import (
	"crypto/subtle"

	"github.com/safechildhood/auth/pkg/crypto"
	"golang.org/x/crypto/argon2"
)

type Argon2Config struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	KeyLength   uint32
	SaltLength  uint32
}

func (hm *HashingManager) getDefaultArgon2Config() (Argon2Config, error) {
	switch hm.algorithmType {
	case Argon2Interactive:
		return Argon2Config{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: 4,
			KeyLength:   32,
			SaltLength:  16,
		}, nil
	case Argon2Moderate:
		return Argon2Config{
			Memory:      256 * 1024,
			Iterations:  6,
			Parallelism: 4,
			KeyLength:   32,
			SaltLength:  16,
		}, nil
	case Argon2Sensitive:
		return Argon2Config{
			Memory:      512 * 1024,
			Iterations:  12,
			Parallelism: 4,
			KeyLength:   32,
			SaltLength:  16,
		}, nil
	default:
		return Argon2Config{}, crypto.ErrUnknownAlgorithmType
	}
}

func (hm *HashingManager) hashArgon2(data []byte, salt []byte) ([]byte, error) {
	if len(salt) != 0 && len(salt) < int(hm.argon2Config.SaltLength) {
		return nil, crypto.ErrArgon2SaltLengthShort
	}

	if len(salt) == 0 {
		salt = []byte{}
	}

	usedSalt := salt
	if len(usedSalt) > int(hm.argon2Config.SaltLength) {
		usedSalt = usedSalt[:hm.argon2Config.SaltLength]
	}

	hash := argon2.IDKey(
		data,
		usedSalt,
		hm.argon2Config.Iterations,
		hm.argon2Config.Memory,
		hm.argon2Config.Parallelism,
		hm.argon2Config.KeyLength,
	)

	return hash, nil
}

func (hm *HashingManager) verifyArgon2(data, salt, expectedHash []byte) (bool, error) {
	hash, err := hm.hashArgon2(data, salt)
	if err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare(hash, expectedHash) == 1, nil
}

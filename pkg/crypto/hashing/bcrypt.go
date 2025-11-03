package hashing

import (
	"github.com/safechildhood/auth/pkg/crypto"
	"golang.org/x/crypto/bcrypt"
)

func (hm *HashingManager) hashBcrypt(data []byte, salt []byte) ([]byte, error) {
	var cost int

	switch hm.algorithmType {
	case Bcrypt:
		cost = 12
	case BcryptMin:
		cost = 4
	case BcryptMax:
		cost = 31
	default:
		return nil, crypto.ErrUnknownAlgorithmType
	}

	updatedData := data

	if len(salt) > 0 {
		updatedData = append(salt, data...)
	}

	hash, err := bcrypt.GenerateFromPassword(updatedData, cost)
	if err != nil {
		return nil, err
	}

	return hash, nil
}

func (hm *HashingManager) verifyBcrypt(data []byte, salt []byte, expectedHash []byte) (bool, error) {
	updatedData := data

	if len(salt) > 0 {
		updatedData = append(salt, data...)
	}

	if err := bcrypt.CompareHashAndPassword(expectedHash, updatedData); err != nil {
		return false, err
	}

	return true, nil
}

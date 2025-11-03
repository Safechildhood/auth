package manager

import (
	"github.com/safechildhood/auth/pkg/crypto"
	"github.com/safechildhood/auth/pkg/crypto/asymmetric"
	"github.com/safechildhood/auth/pkg/crypto/hashing"
	"github.com/safechildhood/auth/pkg/crypto/symmetric"
)

type Crypto interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	Hash(data, salt []byte) ([]byte, error)
	VerifyHash(data, salt, expectedHash []byte) (bool, error)
}

type Callbacks struct {
	EncryptFunc func(plaintext []byte) ([]byte, error)
	DecryptFunc func(ciphertext []byte) ([]byte, error)

	HashFunc       func(data, salt []byte) ([]byte, error)
	VerifyHashFunc func(data, salt, expectedHash []byte) (bool, error)
}

type CryptoManager struct {
	symmetricManager  symmetric.Symmetric
	asymmetricManager asymmetric.Asymmetric
	hashingManager    hashing.Hashing
	callbacks         Callbacks
}

func NewCryptoManager(
	symmetricManager symmetric.Symmetric,
	asymmetricManager asymmetric.Asymmetric,
	hashingManager hashing.Hashing,
	callbacks Callbacks,
) (*CryptoManager, error) {
	if (symmetricManager == nil &&
		asymmetricManager == nil &&
		callbacks.EncryptFunc == nil &&
		callbacks.DecryptFunc == nil) &&

		(hashingManager == nil &&
			callbacks.HashFunc == nil &&
			callbacks.VerifyHashFunc == nil) {

		return nil, crypto.ErrNoManagerProvided
	}

	if symmetricManager != nil && asymmetricManager != nil {
		if callbacks.EncryptFunc == nil || callbacks.DecryptFunc == nil {
			return nil, crypto.ErrNoCallbackFunctionsProvided
		}
	}

	if (callbacks.EncryptFunc == nil) != (callbacks.DecryptFunc == nil) {
		return nil, crypto.ErrNoCallbackFunctionsProvided
	}

	if (callbacks.HashFunc == nil) != (callbacks.VerifyHashFunc == nil) {
		return nil, crypto.ErrNoCallbackFunctionsProvided
	}

	return &CryptoManager{
		symmetricManager:  symmetricManager,
		asymmetricManager: asymmetricManager,
		hashingManager:    hashingManager,
		callbacks:         callbacks,
	}, nil
}

func (cm *CryptoManager) Encrypt(plaintext []byte) ([]byte, error) {
	var (
		ciphertext []byte
		err        error
	)

	if cm.callbacks.EncryptFunc == nil {
		if cm.symmetricManager == nil && cm.asymmetricManager == nil {
			return nil, crypto.ErrNoManagerProvided
		}

		if cm.symmetricManager != nil {
			ciphertext, err = cm.symmetricManager.Encrypt(plaintext)
		} else {
			ciphertext, err = cm.asymmetricManager.Encrypt(plaintext)
		}
	} else {
		ciphertext, err = cm.callbacks.EncryptFunc(plaintext)
	}

	return ciphertext, err
}

func (cm *CryptoManager) Decrypt(ciphertext []byte) ([]byte, error) {
	var (
		plaintext []byte
		err       error
	)

	if cm.callbacks.DecryptFunc == nil {
		if cm.symmetricManager == nil && cm.asymmetricManager == nil {
			return nil, crypto.ErrNoManagerProvided
		}

		if cm.symmetricManager != nil {
			plaintext, err = cm.symmetricManager.Decrypt(ciphertext)
		} else {
			plaintext, err = cm.asymmetricManager.Decrypt(ciphertext)
		}

	} else {
		plaintext, err = cm.callbacks.DecryptFunc(ciphertext)
	}

	return plaintext, err
}

func (cm *CryptoManager) Hash(data, salt []byte) ([]byte, error) {
	var (
		hash []byte
		err  error
	)

	if cm.callbacks.HashFunc == nil {
		if cm.hashingManager == nil {
			return nil, crypto.ErrNoManagerProvided
		}

		hash, err = cm.hashingManager.Hash(data, salt)

	} else {
		hash, err = cm.callbacks.HashFunc(data, salt)
	}

	return hash, err
}

func (cm *CryptoManager) VerifyHash(data, salt, expectedHash []byte) (bool, error) {
	var (
		isVerified bool
		err        error
	)

	if cm.callbacks.VerifyHashFunc == nil {
		if cm.hashingManager == nil {
			return false, crypto.ErrNoManagerProvided
		}

		isVerified, err = cm.hashingManager.VerifyHash(data, salt, expectedHash)

	} else {
		isVerified, err = cm.callbacks.VerifyHashFunc(data, salt, expectedHash)
	}

	return isVerified, err
}

// func (cm *CryptoManager) Sign(data []byte) ([]byte, error) {
// }
//
// func (cm *CryptoManager) VerifySign(data, expectedSign []byte) ([]byte, error) {
// }

package symmetric

import (
	"github.com/safechildhood/auth/pkg/crypto"
)

type AlgorithmType string

const (
	AES128 AlgorithmType = "aes-128"
	AES192 AlgorithmType = "aes-192"
	AES256 AlgorithmType = "aes-256"

	ChaCha20          AlgorithmType = "chacha20"
	ChaCha20Poly1305  AlgorithmType = "chacha20-poly1305"
	XChaCha20         AlgorithmType = "xchacha20"
	XChaCha20Poly1305 AlgorithmType = "xchacha20-poly1305"
)

func (al AlgorithmType) Size() int {
	switch al {
	case AES128:
		return 16
	case AES192:
		return 24
	case AES256:
		return 32
	case ChaCha20, ChaCha20Poly1305, XChaCha20, XChaCha20Poly1305:
		return 32
	default:
		return 0
	}
}

func (al AlgorithmType) Type() string {
	return string(al)
}

type Symmetric interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type SymmetricManager struct {
	algorithmType AlgorithmType

	secretKey []byte
}

func NewManager(algorithmType AlgorithmType, secretKey []byte) (*SymmetricManager, error) {
	switch algorithmType {
	case AES128, AES192, AES256,
		ChaCha20, ChaCha20Poly1305, XChaCha20, XChaCha20Poly1305:
	default:
		return nil, crypto.ErrUnknownAlgorithmType
	}

	return &SymmetricManager{
		algorithmType: algorithmType,
		secretKey:     secretKey,
	}, nil
}

func (sm *SymmetricManager) Encrypt(plaintext []byte) ([]byte, error) {
	switch sm.algorithmType {
	case AES128, AES192, AES256:
		return sm.encryptAES(plaintext)
	case ChaCha20, ChaCha20Poly1305, XChaCha20, XChaCha20Poly1305:
		return sm.encryptChaCha(plaintext)
	default:
		return nil, crypto.ErrUnknownAlgorithmType
	}
}

func (sm *SymmetricManager) Decrypt(ciphertext []byte) ([]byte, error) {
	switch sm.algorithmType {
	case AES128, AES192, AES256:
		return sm.decryptAES(ciphertext)
	case ChaCha20, ChaCha20Poly1305, XChaCha20, XChaCha20Poly1305:
		return sm.decryptChaCha(ciphertext)
	default:
		return nil, crypto.ErrUnknownAlgorithmType
	}
}

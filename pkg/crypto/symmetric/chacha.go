package symmetric

import (
	"crypto/cipher"
	"crypto/rand"

	"github.com/safechildhood/auth/pkg/crypto"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

func (sm *SymmetricManager) encryptChaCha(plaintext []byte) ([]byte, error) {
	var nonceSize int

	switch sm.algorithmType {
	case ChaCha20:
		nonceSize = chacha20.NonceSize
	case XChaCha20:
		nonceSize = chacha20.NonceSizeX
	case ChaCha20Poly1305:
		nonceSize = chacha20poly1305.NonceSize
	case XChaCha20Poly1305:
		nonceSize = chacha20poly1305.NonceSizeX
	default:
		return nil, crypto.ErrUnknownAlgorithmType
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	var ciphertext []byte

	switch sm.algorithmType {
	case ChaCha20, XChaCha20:
		ciphertext := make([]byte, len(plaintext))
		cipher, err := chacha20.NewUnauthenticatedCipher(sm.secretKey, nonce)
		if err != nil {
			return nil, err
		}

		cipher.XORKeyStream(ciphertext, plaintext)

	case ChaCha20Poly1305, XChaCha20Poly1305:
		var (
			aead cipher.AEAD
			err  error
		)

		switch sm.algorithmType {
		case ChaCha20Poly1305:
			aead, err = chacha20poly1305.New(sm.secretKey)
		case XChaCha20Poly1305:
			aead, err = chacha20poly1305.NewX(sm.secretKey)
		}

		if err != nil {
			return nil, err
		}

		ciphertext = aead.Seal(nil, nonce, plaintext, nil)
	}

	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result[:len(nonce)], nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

func (sm *SymmetricManager) decryptChaCha(data []byte) ([]byte, error) {
	var nonceSize int

	switch sm.algorithmType {
	case ChaCha20:
		nonceSize = chacha20.NonceSize
	case XChaCha20:
		nonceSize = chacha20.NonceSizeX
	case ChaCha20Poly1305:
		nonceSize = chacha20poly1305.NonceSize
	case XChaCha20Poly1305:
		nonceSize = chacha20poly1305.NonceSizeX
	default:
		return nil, crypto.ErrUnknownAlgorithmType
	}

	if len(data) < nonceSize {
		return nil, crypto.ErrCipherTextInvalidLength
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	var plaintext []byte

	switch sm.algorithmType {
	case ChaCha20, XChaCha20:
		plaintext := make([]byte, len(ciphertext))
		cipher, err := chacha20.NewUnauthenticatedCipher(sm.secretKey, nonce)
		if err != nil {
			return nil, err
		}

		cipher.XORKeyStream(plaintext, ciphertext)

	case ChaCha20Poly1305, XChaCha20Poly1305:
		var (
			aead cipher.AEAD
			err  error
		)

		switch sm.algorithmType {
		case ChaCha20Poly1305:
			aead, err = chacha20poly1305.New(sm.secretKey)
		case XChaCha20Poly1305:
			aead, err = chacha20poly1305.NewX(sm.secretKey)
		}

		if err != nil {
			return nil, err
		}

		plaintext, err = aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, err
		}
	}

	return plaintext, nil
}

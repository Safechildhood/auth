package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/safechildhood/auth/pkg/crypto"
)

func (sm *SymmetricManager) encryptAES(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(sm.secretKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (sm *SymmetricManager) decryptAES(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(sm.secretKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, crypto.ErrCipherTextInvalidLength
	}

	nonce, ciphertextOnly := ciphertext[:nonceSize], ciphertext[nonceSize:]

	return gcm.Open(nil, nonce, ciphertextOnly, nil)
}

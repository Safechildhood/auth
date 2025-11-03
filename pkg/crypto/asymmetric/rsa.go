package asymmetric

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/safechildhood/auth/pkg/crypto"
)

func (am *AsymmetricManager) encryptRSA(plaintext []byte) ([]byte, error) {
	publicKey, err := am.publicKeyToRSA()
	if err != nil {
		return nil, err
	}

	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, plaintext)
}

func (am *AsymmetricManager) decryptRSA(ciphertext []byte) ([]byte, error) {
	privateKey, err := am.privateKeyToRSA()
	if err != nil {
		return nil, err
	}

	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
}

func (am *AsymmetricManager) publicKeyToRSA() (*rsa.PublicKey, error) {
	block, _ := pem.Decode(am.publicKey)
	if block == nil {
		return nil, crypto.ErrFailedPEMBlockParsing
	}

	untypedPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, crypto.ErrInvalidPKIXKey
	}

	publicKey, ok := untypedPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, crypto.ErrInvalidPublicKey
	}

	return publicKey, nil
}

func (am *AsymmetricManager) privateKeyToRSA() (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(am.privateKey)
	if block == nil {
		return nil, crypto.ErrFailedPEMBlockParsing
	}

	untypedPrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, crypto.ErrInvalidPKIXKey
	}

	privateKey, ok := untypedPrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, crypto.ErrInvalidPrivateKey
	}

	return privateKey, nil
}

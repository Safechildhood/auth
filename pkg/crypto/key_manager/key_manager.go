package keymanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"

	"github.com/safechildhood/auth/pkg/crypto"
	"github.com/safechildhood/auth/pkg/crypto/asymmetric"
	"github.com/safechildhood/auth/pkg/crypto/symmetric"
)

func LoadKeyPair(privateFilename, publicFilename string) (privateKey, publicKey []byte, err error) {
	privateKey, err = os.ReadFile(privateFilename)
	if err != nil {
		return nil, nil, err
	}

	publicKey, err = os.ReadFile(publicFilename)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

func LoadSecretKey(filename string) (secretKey []byte, err error) {
	return os.ReadFile(filename)
}

func GenerateKeyPair(algorithmType asymmetric.AlgorithmType) (privateKey, publicKey []byte, err error) {
	switch algorithmType {
	case asymmetric.RSA1024,
		asymmetric.RSA2048,
		asymmetric.RSA3072,
		asymmetric.RSA4096,
		asymmetric.RSA8192:
		return generateRSAKeyPair(algorithmType.Size() * 8)
	case asymmetric.P224,
		asymmetric.P256,
		asymmetric.P384,
		asymmetric.P521:
		return generateECKeyPair(algorithmType.Size())
	default:
		return nil, nil, crypto.ErrUnknownAlgorithmType
	}
}

func GenerateSecretKey(algorithmType symmetric.AlgorithmType) (secretKey []byte, err error) {
	switch algorithmType {
	case symmetric.AES128, symmetric.AES192, symmetric.AES256, symmetric.ChaCha20, symmetric.ChaCha20Poly1305, symmetric.XChaCha20, symmetric.XChaCha20Poly1305:
	default:
		return nil, crypto.ErrUnknownAlgorithmType
	}

	key := make([]byte, algorithmType.Size())
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, crypto.ErrFailedKeyGeneration
	}

	return key, nil
}

func generateRSAKeyPair(bits int) (privateKey, publicKey []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, crypto.ErrFailedKeyGeneration
	}

	if err := priv.Validate(); err != nil {
		return nil, nil, crypto.ErrFailedKeyGeneration
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, crypto.ErrFailedKeyGeneration
	}
	privBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}
	privateKey = pem.EncodeToMemory(privBlock)

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, crypto.ErrFailedKeyGeneration
	}
	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	publicKey = pem.EncodeToMemory(pubBlock)

	return privateKey, publicKey, nil
}

func generateECKeyPair(bits int) (privateKey, publicKey []byte, err error) {
	var curve elliptic.Curve

	switch bits {
	case 28:
		curve = elliptic.P224()
	case 32:
		curve = elliptic.P256()
	case 48:
		curve = elliptic.P384()
	case 66:
		curve = elliptic.P521()
	default:
		return nil, nil, crypto.ErrUnknownKeySize
	}

	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	privBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	}

	privateKey = pem.EncodeToMemory(privBlock)

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}

	publicKey = pem.EncodeToMemory(pubBlock)

	return privateKey, publicKey, nil
}

func SaveKeyPair(privateFilename, publicFilename string, privateKey, publicKey []byte) error {
	if err := os.WriteFile(privateFilename, privateKey, 0600); err != nil {
		return err
	}

	if err := os.WriteFile(publicFilename, privateKey, 0600); err != nil {
		return os.Remove(privateFilename)
	}

	return nil
}

func SaveSecretKey(filename string, secretKey []byte) error {
	return os.WriteFile(filename, secretKey, 0600)
}

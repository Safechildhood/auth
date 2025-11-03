package asymmetric

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"

	"github.com/safechildhood/auth/pkg/crypto"
)

const SaltSize int = 32

func (am *AsymmetricManager) encryptEC(plaintext []byte) ([]byte, error) {
	var curve elliptic.Curve

	switch am.algorithmType {
	case P224:
		curve = elliptic.P224()
	case P256:
		curve = elliptic.P256()
	case P384:
		curve = elliptic.P384()
	case P521:
		curve = elliptic.P521()
	default:
		return nil, crypto.ErrUnknownAlgorithmType
	}

	publicKey, err := am.publicKeyToEC()
	if err != nil {
		return nil, err
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	sharedX, sharedY := curve.ScalarMult(publicKey.X, publicKey.Y, privateKey.D.Bytes())

	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	mask := deriveSecureMask(sharedX.Bytes(), sharedY.Bytes(), salt)

	ciphertext := make([]byte, len(plaintext))
	for i := range plaintext {
		ciphertext[i] = plaintext[i] ^ mask[i%len(mask)]
	}

	return am.packDataForEC(
		privateKey.X.Bytes(),
		privateKey.Y.Bytes(),
		salt,
		ciphertext,
	), nil
}

func (am *AsymmetricManager) decryptEC(ciphertext []byte) ([]byte, error) {
	var curve elliptic.Curve

	switch am.algorithmType {
	case P224:
		curve = elliptic.P224()
	case P256:
		curve = elliptic.P256()
	case P384:
		curve = elliptic.P384()
	case P521:
		curve = elliptic.P521()
	default:
		return nil, crypto.ErrUnknownAlgorithmType
	}

	privateKey, err := am.privateKeyToEC()
	if err != nil {
		return nil, err
	}

	ephemX, ephemY, salt, ciphertext, err := am.unpackDataForEC(ciphertext)
	if err != nil {
		return nil, err
	}

	sharedX, sharedY := curve.ScalarMult(ephemX, ephemY, privateKey.D.Bytes())

	mask := deriveSecureMask(sharedX.Bytes(), sharedY.Bytes(), salt)

	plaintext := make([]byte, len(ciphertext))
	for i := range ciphertext {
		plaintext[i] = ciphertext[i] ^ mask[i%len(mask)]
	}

	return plaintext, nil
}

func (am *AsymmetricManager) privateKeyToEC() (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(am.privateKey)
	if block == nil {
		return nil, crypto.ErrFailedPEMBlockParsing
	}

	untypedPrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, crypto.ErrInvalidPEMBlock
	}

	privateKey, ok := untypedPrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, crypto.ErrInvalidPrivateKey
	}

	return privateKey, nil
}

func (am *AsymmetricManager) publicKeyToEC() (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(am.publicKey)
	if block == nil {
		return nil, crypto.ErrFailedPEMBlockParsing
	}

	untypedPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, crypto.ErrInvalidPKIXKey
	}

	publicKey, ok := untypedPublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, crypto.ErrInvalidPublicKey
	}

	return publicKey, nil
}

func (am *AsymmetricManager) packDataForEC(ephemX, ephemY, salt, ciphertext []byte) []byte {
	xBytes := fixSize(ephemX, am.algorithmType.Size())
	yBytes := fixSize(ephemY, am.algorithmType.Size())

	totalSize := 2*am.algorithmType.Size() + SaltSize + 4 + len(ciphertext)
	result := make([]byte, totalSize)
	offset := 0

	copy(result[offset:], xBytes)
	offset += am.algorithmType.Size()

	copy(result[offset:], yBytes)
	offset += am.algorithmType.Size()

	copy(result[offset:], salt)
	offset += SaltSize

	binary.BigEndian.PutUint32(result[offset:], uint32(len(ciphertext)))
	offset += 4
	copy(result[offset:], ciphertext)

	return result
}

func (am *AsymmetricManager) unpackDataForEC(data []byte) (ephemX *big.Int, ephemY *big.Int, salt []byte, ciphertext []byte, err error) {
	if len(data) < 2*am.algorithmType.Size()+SaltSize+4 {
		return nil, nil, nil, nil, crypto.ErrCipherTextInvalidLength
	}

	offset := 0

	ephemX = new(big.Int).SetBytes(data[offset : offset+am.algorithmType.Size()])
	offset += am.algorithmType.Size()

	ephemY = new(big.Int).SetBytes(data[offset : offset+am.algorithmType.Size()])
	offset += am.algorithmType.Size()

	salt = make([]byte, SaltSize)
	copy(salt, data[offset:offset+SaltSize])
	offset += SaltSize

	cipherTextLength := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	if offset+cipherTextLength > len(data) {
		return nil, nil, nil, nil, crypto.ErrCipherTextInvalidLength
	}

	ciphertext = make([]byte, cipherTextLength)
	copy(ciphertext, data[offset:offset+cipherTextLength])

	return ephemX, ephemY, salt, ciphertext, nil
}

func fixSize(data []byte, size int) []byte {
	if len(data) == size {
		return data
	}

	result := make([]byte, size)
	if len(data) > size {
		copy(result, data[:size])
	} else {
		copy(result[size-len(data):], data)
	}

	return result
}

func deriveSecureMask(sharedX, sharedY, salt []byte) []byte {
	h := sha512.New()

	h.Write(sharedX)
	h.Write(sharedY)
	h.Write(salt)
	hash1 := h.Sum(nil)

	h.Reset()
	h.Write(hash1)
	h.Write(salt)
	finalHash := h.Sum(nil)

	return finalHash
}

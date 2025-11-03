package hashing

import (
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"crypto/subtle"
	"hash"

	"github.com/safechildhood/auth/pkg/crypto"
)

func (hm *HashingManager) hashSHA(data []byte, salt []byte) ([]byte, error) {
	var hasher hash.Hash

	switch hm.algorithmType {
	case SHA224:
		hasher = sha256.New224()
	case SHA256:
		hasher = sha256.New()
	case SHA384:
		hasher = sha512.New384()
	case SHA512:
		hasher = sha512.New()
	case SHA512_224:
		hasher = sha512.New512_224()
	case SHA512_256:
		hasher = sha512.New512_256()
	case SHA3_224:
		hasher = sha3.New224()
	case SHA3_256:
		hasher = sha3.New256()
	case SHA3_384:
		hasher = sha3.New384()
	case SHA3_512:
		hasher = sha3.New512()
	default:
		return nil, crypto.ErrUnknownAlgorithmType
	}

	if len(salt) > 0 {
		hasher.Write(salt)
	}

	hasher.Write(data)

	return hasher.Sum(nil), nil
}

func (hm *HashingManager) verifySHA(data, salt, expectedHash []byte) (bool, error) {
	hash, err := hm.hashSHA(data, salt)
	if err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare(expectedHash, hash) == 1, nil
}

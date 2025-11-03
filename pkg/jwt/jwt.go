package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
)

type Manager interface {
	CreateToken(claims jwt.Claims) (string, error)
	ParseAndValidateToken(tokenString string) (jwt.Claims, bool, error)
}

type Keys struct {
	HmacKey []byte

	RsaPrivateKey *rsa.PrivateKey
	RsaPublicKey  *rsa.PublicKey

	EcdsaPrivateKey *ecdsa.PrivateKey
	EcdsaPublicKey  *ecdsa.PublicKey

	Ed25519PrivateKey *ed25519.PrivateKey
	Ed25519PublicKey  *ed25519.PublicKey
}

type TokenManager struct {
	signingMethod jwt.SigningMethod

	keys Keys
}

func NewTokenManager(signingMethod jwt.SigningMethod, keys Keys) (*TokenManager, error) {
	switch signingMethod.Alg()[:2] {
	case "HS":
		if len(keys.HmacKey) == 0 {
			return nil, ErrNoKeysProvided
		}
	case "RS", "PS":
		if keys.RsaPrivateKey == nil || keys.RsaPublicKey == nil {
			return nil, ErrNoKeysProvided
		}
	case "ES":
		if keys.EcdsaPrivateKey == nil || keys.EcdsaPublicKey == nil {
			return nil, ErrNoKeysProvided
		}
	case "Ed":
		if keys.Ed25519PrivateKey == nil || keys.Ed25519PublicKey == nil {
			return nil, ErrNoKeysProvided
		}
	default:
		return nil, ErrUnexpectedSigningMethod
	}

	return &TokenManager{
		signingMethod: signingMethod,
		keys:          keys,
	}, nil
}

func (tm *TokenManager) CreateToken(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(tm.signingMethod, claims)

	var (
		tokenString string
		err         error
	)

	switch tm.signingMethod.Alg()[:2] {
	case "HS":
		tokenString, err = token.SignedString(tm.keys.HmacKey)
	case "RS", "PS":
		tokenString, err = token.SignedString(tm.keys.RsaPrivateKey)
	case "ES":
		tokenString, err = token.SignedString(tm.keys.EcdsaPrivateKey)
	case "Ed":
		tokenString, err = token.SignedString(tm.keys.Ed25519PrivateKey)
	default:
		return "", ErrUnexpectedSigningMethod
	}

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (tm *TokenManager) ParseAndValidateToken(tokenString string) (jwt.Claims, bool, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		var key any

		switch token.Header["alg"].(string)[:2] {
		case "HS":
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, ErrUnexpectedSigningMethod
			}

			key = tm.keys.HmacKey

		case "RS":
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, ErrUnexpectedSigningMethod
			}

			key = tm.keys.RsaPublicKey

		case "ES":
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, ErrUnexpectedSigningMethod
			}

			key = tm.keys.EcdsaPublicKey

		case "PS":
			if _, ok := token.Method.(*jwt.SigningMethodRSAPSS); !ok {
				return nil, ErrUnexpectedSigningMethod
			}

			key = tm.keys.RsaPublicKey

		case "Ed":
			if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, ErrUnexpectedSigningMethod
			}

			key = tm.keys.Ed25519PublicKey

		default:
			return nil, ErrUnexpectedSigningMethod
		}

		return key, nil
	})
	if err != nil {
		return nil, false, err
	}

	if !token.Valid {
		return nil, false, nil
	}

	return token.Claims, true, nil
}

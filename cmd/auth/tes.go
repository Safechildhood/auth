package main

import (
	"encoding/json"
	"fmt"

	"github.com/safechildhood/auth/pkg/crypto/hashing"
	"github.com/safechildhood/auth/pkg/crypto/manager"
)

// TODO: remove blacklist

func m() {
	m := map[string]any{
		"k1": "v1",
		"k2": "v2",
		"k3": map[string]any{
			"k4": "v4",
		},
	}

	body, _ := json.Marshal(m)
	fmt.Println(string(body))

	var cm manager.Crypto
	{
		var argon2 hashing.Hashing
		{
			var err error
			argon2, err = hashing.NewManager(hashing.Argon2Sensitive)
			if err != nil {
				panic(err)
			}

		}
		var err error

		cm, err = manager.NewCryptoManager(nil, nil, argon2, manager.Callbacks{})
		if err != nil {
			panic(err)
		}
	}
	text := "yomaextradifficultpassword"
	hash, err := cm.Hash([]byte(text), []byte("freesaltasdasdsad"))
	if err != nil {
		panic(err)
	}

	fmt.Println(string(hash))
	// var cm manager.Crypto
	// {
	// 	var chacha symmetric.Symmetric
	// 	{
	// 		secretKey, err := keymanager.GenerateSecretKey(symmetric.XChaCha20Poly1305)
	// 		if err != nil {
	// 			panic(err)
	// 		}
	//
	// 		chacha, err = symmetric.NewManager(symmetric.XChaCha20Poly1305, secretKey)
	// 		if err != nil {
	// 			panic(err)
	// 		}
	//
	// 	}
	//
	// 	var aes symmetric.Symmetric
	// 	{
	// 		secretKey, err := keymanager.GenerateSecretKey(symmetric.AES256)
	// 		if err != nil {
	// 			panic(err)
	// 		}
	//
	// 		aes, err = symmetric.NewManager(symmetric.AES256, secretKey)
	// 		if err != nil {
	// 			panic(err)
	// 		}
	// 	}
	//
	// 	var rsa asymmetric.Asymmetric
	// 	{
	// 		privateKey, publicKey, err := keymanager.GenerateKeyPair(asymmetric.RSA4096)
	// 		if err != nil {
	// 			panic(err)
	// 		}
	//
	// 		rsa, err = asymmetric.NewManager(asymmetric.RSA4096, publicKey, privateKey)
	// 		if err != nil {
	// 			panic(err)
	// 		}
	//
	// 	}
	//
	// 	var ec asymmetric.Asymmetric
	// 	{
	// 		privateKey, publicKey, err := keymanager.GenerateKeyPair(asymmetric.P521)
	// 		if err != nil {
	// 			panic(err)
	// 		}
	//
	// 		ec, err = asymmetric.NewManager(asymmetric.P521, publicKey, privateKey)
	// 		if err != nil {
	// 			panic(err)
	// 		}
	// 	}
	//
	// 	callbacks := manager.Callbacks{
	// 		EncryptFunc: func(plaintext []byte) ([]byte, error) {
	// 			c1, err := ec.Encrypt(plaintext)
	// 			if err != nil {
	// 				return nil, err
	// 			}
	//
	// 			fmt.Printf("encrypted #1: %s \n", string(c1))
	//
	// 			c2, err := rsa.Encrypt(c1)
	// 			if err != nil {
	// 				return nil, err
	// 			}
	//
	// 			fmt.Printf("encrypted #2: %s \n", string(c2))
	//
	// 			c3, err := aes.Encrypt(c2)
	// 			if err != nil {
	// 				return nil, err
	// 			}
	//
	// 			fmt.Printf("encrypted #3: %s \n", string(c3))
	//
	// 			c4, err := chacha.Encrypt(c3)
	// 			if err != nil {
	// 				return nil, err
	// 			}
	//
	// 			fmt.Printf("encrypted #4: %s \n", string(c4))
	//
	// 			return c4, nil
	// 		},
	// 		DecryptFunc: func(ciphertext []byte) ([]byte, error) {
	// 			p1, err := chacha.Decrypt(ciphertext)
	// 			if err != nil {
	// 				return nil, err
	// 			}
	//
	// 			fmt.Printf("decrypted #1: %s \n", string(p1))
	//
	// 			p2, err := aes.Decrypt(p1)
	// 			if err != nil {
	// 				return nil, err
	// 			}
	//
	// 			fmt.Printf("decrypted #2: %s \n", string(p2))
	//
	// 			p3, err := rsa.Decrypt(p2)
	// 			if err != nil {
	// 				return nil, err
	// 			}
	//
	// 			fmt.Printf("decrypted #3: %s \n", string(p3))
	//
	// 			p4, err := ec.Decrypt(p3)
	// 			if err != nil {
	// 				return nil, err
	// 			}
	//
	// 			fmt.Printf("decrypted #4: %s \n", string(p4))
	//
	// 			return p4, nil
	// 		},
	// 	}
	//
	// 	var err error
	//
	// 	cm, err = manager.NewCryptoManager(nil, nil, nil, callbacks)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// }
	//
	// text := "modafinil"
	//
	// ciphertext, err := cm.Encrypt([]byte(text))
	// if err != nil {
	// 	panic(err)
	// }
	//
	// plaintext, err := cm.Decrypt(ciphertext)
	// if err != nil {
	// 	panic(err)
	// }
	//
	// fmt.Printf("\ninput_text: %s\nresult: %s\n", text, string(plaintext))
	//
	// fmt.Println(bytes.Equal([]byte(text), plaintext))
}

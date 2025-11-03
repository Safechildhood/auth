package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strconv"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/safechildhood/auth/internal/config"
	"github.com/safechildhood/auth/internal/handler"
	"github.com/safechildhood/auth/internal/repository"
	"github.com/safechildhood/auth/internal/repository/postgresql"
	"github.com/safechildhood/auth/internal/repository/valkey"
	"github.com/safechildhood/auth/internal/service"
	"github.com/safechildhood/auth/pkg/crypto"
	"github.com/safechildhood/auth/pkg/crypto/asymmetric"
	"github.com/safechildhood/auth/pkg/crypto/hashing"
	keymanager "github.com/safechildhood/auth/pkg/crypto/key_manager"
	"github.com/safechildhood/auth/pkg/crypto/manager"
	jwtmanager "github.com/safechildhood/auth/pkg/jwt"
	glide "github.com/valkey-io/valkey-glide/go/v2"
	glideConfig "github.com/valkey-io/valkey-glide/go/v2/config"
)

func main() {
	config, err := config.New()
	if err != nil {
		panic(err)
	}

	var repositoryVar *repository.Repository
	{
		dsn := fmt.Sprintf(
			"postgresql://%s:%s@%s:%s/%s?sslmode=disable",
			config.MainDatabase.User,
			config.MainDatabase.Password,
			config.MainDatabase.Host,
			config.MainDatabase.Port,
			config.MainDatabase.Name,
		)

		pool, err := pgxpool.New(context.Background(), dsn)
		if err != nil {
			panic(err)
		}

		port, err := strconv.Atoi(config.TemporaryDatabase.Port)
		if err != nil {
			panic(err)
		}

		clientConfig := glideConfig.NewClientConfiguration().
			WithAddress(&glideConfig.NodeAddress{
				Host: config.TemporaryDatabase.Host,
				Port: port,
			}).WithCredentials(glideConfig.NewServerCredentialsWithDefaultUsername(config.TemporaryDatabase.Password))

		client, err := glide.NewClient(clientConfig)
		if err != nil {
			panic(err)
		}

		usersRepository := postgresql.NewUsers(pool, config.MainDatabase.Users.Name)

		temporaryUsersRepository := valkey.NewTemporaryUsers(client, config.TemporaryDatabase.TemporaryUsers.Name)

		verificationCodesRepository := valkey.NewVerificationCodes(
			client,
			config.TemporaryDatabase.VerificationCodes.Name,
			config.TemporaryDatabase.VerificationCodes.User,
		)

		refreshTokensRepository := valkey.NewRefreshTokens(
			client,
			config.TemporaryDatabase.RefreshTokens.Name,
			config.TemporaryDatabase.RefreshTokens.User,
		)

		blacklistRepository := valkey.NewBlacklist(
			client,
			config.TemporaryDatabase.Blacklist.Name,
			config.TemporaryDatabase.Blacklist.AccessTokens,
		)

		repositoryVar = repository.New(
			usersRepository,
			temporaryUsersRepository,
			verificationCodesRepository,
			refreshTokensRepository,
			blacklistRepository,
		)
	}

	var serviceVar *service.Service
	{
		var usersService service.Users
		{
			hashing, err := hashing.NewManager(hashing.Argon2Moderate)
			if err != nil {
				panic(err)
			}

			cryptoManager, err := manager.NewCryptoManager(nil, nil, hashing, manager.Callbacks{})
			if err != nil {
				panic(err)
			}

			usersService = service.NewUsersService(
				repositoryVar.Users,
				repositoryVar.TemporaryUsers,
				config.Auth.TemporaryUser.TTL,
				config.Auth.User.SaltLength,
				cryptoManager,
			)
		}

		uri := fmt.Sprintf(
			"amqp://%s:%s@%s:%s%s",
			config.Broker.User,
			config.Broker.Password,
			config.Broker.Host,
			config.Broker.Port,
			config.Broker.VHost,
		)

		mailService, err := service.NewMailService(uri)
		if err != nil {
			panic(err)
		}

		verificationCodesService := service.NewVerificationCodesService(
			repositoryVar.VerifcationCodes,
			config.Auth.VerificationCode.TTL,
			config.Auth.VerificationCode.ResendTTL,
			config.Auth.VerificationCode.Length,
		)

		var accessTokensService service.AccessTokens
		{
			var jwtManager jwtmanager.Manager
			{
				privateKeyByte, publicKeyByte, err := keymanager.GenerateKeyPair(asymmetric.P521)
				if err != nil {
					panic(err)
				}

				privateKey, err := privateKeyToEC(privateKeyByte)
				if err != nil {
					panic(err)
				}

				publicKey, err := publicKeyToEC(publicKeyByte)
				if err != nil {
					panic(err)
				}

				jwtManager, err = jwtmanager.NewTokenManager(jwt.SigningMethodES512, jwtmanager.Keys{
					EcdsaPrivateKey: privateKey,
					EcdsaPublicKey:  publicKey,
				})
				if err != nil {
					panic(err)
				}
			}

			var cryptoManager manager.Crypto
			{
				hashing, err := hashing.NewManager(hashing.SHA512)
				if err != nil {
					panic(err)
				}

				cryptoManager, err = manager.NewCryptoManager(nil, nil, hashing, manager.Callbacks{})
				if err != nil {
					panic(err)
				}

			}

			accessTokensService = service.NewAccessTokensService(
				repositoryVar.Blacklist,
				config.Auth.AccessToken.TTL,
				jwtManager,
				cryptoManager,
			)
		}

		var refreshTokensService service.RefreshTokens
		{
			var cryptoManager manager.Crypto
			{
				hashing, err := hashing.NewManager(hashing.SHA512)
				if err != nil {
					panic(err)
				}

				cryptoManager, err = manager.NewCryptoManager(nil, nil, hashing, manager.Callbacks{})
				if err != nil {
					panic(err)
				}

			}

			refreshTokensService = service.NewRefreshTokensService(
				repositoryVar.RefreshTokens,
				config.Auth.RefreshToken.TTL,
				cryptoManager,
			)
		}

		authService := service.NewAuthService(
			usersService,
			mailService,
			verificationCodesService,
			accessTokensService,
			refreshTokensService,
		)

		serviceVar = service.New(authService)
	}

	handlerVar := handler.New(serviceVar, &config.Server)
	handlerVar.Init()

	if err := handlerVar.Start(); err != nil {
		panic(err)
	}
}

func privateKeyToEC(key []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
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

func publicKeyToEC(key []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(key)
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

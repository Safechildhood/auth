package grpc

import (
	"context"
	"errors"
	"fmt"

	authpb "github.com/safechildhood/auth/api/grpc/auth"
	"github.com/safechildhood/auth/internal/domain"
	"github.com/safechildhood/auth/internal/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

type AuthHandler struct {
	authpb.UnimplementedAuthServiceServer

	authService service.Auth
}

func NewAuthHandler(authService service.Auth) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

func (ah *AuthHandler) Register(ctx context.Context, req *authpb.RegisterRequest) (*authpb.VerificationCodeResponse, error) {
	verificationCodeTTL, err := ah.authService.Register(ctx, service.RegisterInput{
		Email:            req.Email,
		Password:         req.Password,
		SecretPhrase:     req.SecretPhrase,
		SecretPhraseHint: req.SecretPhraseHint,
		Fingerprint:      req.Fingerprint,
	})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrUserAlreadyExists),
			errors.Is(err, domain.ErrVerificationCodeAlreadyExists):
			return nil, status.Error(codes.AlreadyExists, "object already exists")
		default:
			fmt.Println(err)
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	// domain.ErrUserAlreadyExists
	// domain.ErrInvalidFingerprintsHash
	// domain.ErrGeneratingCode
	// domain.ErrVerificationCodeAlreadyExists
	// domain.ErrUnknownEventType

	return &authpb.VerificationCodeResponse{
		VerificationCodeTtl: durationpb.New(verificationCodeTTL),
	}, nil
}

func (ah *AuthHandler) RegisterConfirm(ctx context.Context, req *authpb.ConfirmRequest) (*authpb.TokensResponse, error) {
	tokensOutput, err := ah.authService.RegisterConfirm(ctx, service.ConfirmInput{
		Email:            req.Email,
		VerificationCode: req.VerificationCode,
		Fingerprint:      req.Fingerprint,
	})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrUserNotFound),
			errors.Is(err, domain.ErrFingerprintNotFound),
			errors.Is(err, domain.ErrVerificationCodeNotFound):
			return nil, status.Error(codes.NotFound, "object is not found")
		case errors.Is(err, domain.ErrRefreshTokenAlreadyExists):
			return nil, status.Error(codes.AlreadyExists, "object already exists")
		default:
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	// domain.ErrUserNotFound
	// domain.ErrInvalidID
	// domain.ErrInvalidFingerprintsHash
	// domain.ErrInvalidTime
	// domain.ErrFingerprintNotFound
	// domain.ErrVerificationCodeNotFound
	// domain.ErrRefreshTokenAlreadyExists

	return &authpb.TokensResponse{
		AccessToken:    tokensOutput.AccessToken,
		AccessTokenTtl: durationpb.New(tokensOutput.AccessTokenTTL),
		RefreshToken:   tokensOutput.RefreshToken,
	}, nil
}

func (ah *AuthHandler) ResendCode(ctx context.Context, req *authpb.ResendCodeRequest) (*authpb.VerificationCodeResponse, error) {
	verificationCodeTTL, err := ah.authService.ResendCode(ctx, service.ResendCodeInput{
		Email:       req.Email,
		Fingerprint: req.Fingerprint,
	})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrUserNotFound),
			errors.Is(err, domain.ErrFingerprintNotFound),
			errors.Is(err, domain.ErrVerificationCodeNotFound):
			return nil, status.Error(codes.NotFound, "object is not found")
		case errors.Is(err, domain.ErrVerificationCodeResendTimeout):
			return nil, status.Error(codes.FailedPrecondition, "timeout is not expired")
		case errors.Is(err, domain.ErrVerificationCodeAlreadyExists):
			return nil, status.Error(codes.AlreadyExists, "object already exists")
		default:
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	// domain.ErrUserNotFound
	// domain.ErrFingerprintNotFound
	// domain.ErrInvalidID
	// domain.ErrInvalidFingerprintsHash
	// domain.ErrInvalidTime
	// domain.ErrVerificationCodeNotFound
	// domain.ErrVerificationCodeResendTimeout
	// domain.ErrGeneratingCode
	// domain.ErrVerificationCodeAlreadyExists
	// domain.ErrUnknownEventType

	return &authpb.VerificationCodeResponse{
		VerificationCodeTtl: durationpb.New(verificationCodeTTL),
	}, nil
}

func (ah *AuthHandler) ValidateAction(ctx context.Context, req *authpb.UserSecureRequest) (*authpb.GenericResponse, error) {
	isValid, err := ah.authService.ValidateAction(ctx, service.UserSecureInput{
		AccessToken:  req.AccessToken,
		RefreshToken: req.RefreshToken,
		Fingerprint:  req.Fingerprint,
	})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrRefreshTokenNotFound):
			return nil, status.Error(codes.NotFound, "object is not found")
		case errors.Is(err, domain.ErrInvalidAccessToken),
			errors.Is(err, domain.ErrInvalidRefreshToken),
			errors.Is(err, domain.ErrInvalidFingerprintsHash),
			errors.Is(err, domain.ErrInvalidAction):
			return nil, status.Error(codes.Unauthenticated, "unauthenticated request")
		default:
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	// domain.ErrUnknownObjectType
	// domain.ErrInvalidTime
	// domain.ErrInvalidAccessToken
	// domain.ErrInvalidRefreshToken
	// domain.ErrInvalidID
	// domain.ErrRefreshTokenNotFound

	return &authpb.GenericResponse{
		Success: isValid,
	}, nil
}

func (ah *AuthHandler) UpdateTokens(ctx context.Context, req *authpb.UserSecureRequest) (*authpb.TokensResponse, error) {
	tokensOutput, err := ah.authService.UpdateTokens(ctx, service.UserSecureInput{
		AccessToken:  req.AccessToken,
		RefreshToken: req.RefreshToken,
		Fingerprint:  req.Fingerprint,
	})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrRefreshTokenNotFound):
			return nil, status.Error(codes.NotFound, "object is not found")
		case errors.Is(err, domain.ErrInvalidAccessToken),
			errors.Is(err, domain.ErrInvalidRefreshToken):
			return nil, status.Error(codes.InvalidArgument, "invalid argument")
		case errors.Is(err, domain.ErrInvalidAction):
			return nil, status.Error(codes.Unauthenticated, "unauthenticated request")
		default:
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	// domain.ErrUnknownObjectType
	// domain.ErrInvalidTime
	// domain.ErrInvalidAccessToken
	// domain.ErrInvalidRefreshToken
	// domain.ErrInvalidID
	// domain.ErrRefreshTokenNotFound
	// domain.ErrInvalidAction

	return &authpb.TokensResponse{
		AccessToken:    tokensOutput.AccessToken,
		AccessTokenTtl: durationpb.New(tokensOutput.AccessTokenTTL),
		RefreshToken:   tokensOutput.RefreshToken,
	}, nil
}

func (ah *AuthHandler) Login(ctx context.Context, req *authpb.LoginRequest) (*authpb.LoginResponse, error) {
	loginOutput, err := ah.authService.Login(ctx, service.LoginInput{
		Email:       req.Email,
		Password:    req.Password,
		Fingerprint: req.Fingerprint,
	})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrUserNotFound):
			return nil, status.Error(codes.NotFound, "object is not found")
		case errors.Is(err, domain.ErrInvalidPassword):
			return nil, status.Error(codes.InvalidArgument, "invalid argument")
		case errors.Is(err, domain.ErrRefreshTokenAlreadyExists),
			errors.Is(err, domain.ErrVerificationCodeAlreadyExists):
			return nil, status.Error(codes.AlreadyExists, "object already exists")
		default:
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	// domain.ErrUserNotFound
	// domain.ErrInvalidPassword
	// domain.ErrRefreshTokenAlreadyExists
	// domain.ErrGeneratingCode
	// domain.ErrVerificationCodeAlreadyExists

	response := &authpb.LoginResponse{}
	if (loginOutput.Tokens != service.TokensOutput{}) {
		response.Response = &authpb.LoginResponse_Tokens{
			Tokens: &authpb.TokensResponse{
				AccessToken:    loginOutput.Tokens.AccessToken,
				AccessTokenTtl: durationpb.New(loginOutput.Tokens.AccessTokenTTL),
				RefreshToken:   loginOutput.Tokens.RefreshToken,
			},
		}
	} else {
		response.Response = &authpb.LoginResponse_VerificationCode{
			VerificationCode: &authpb.VerificationCodeResponse{
				VerificationCodeTtl: durationpb.New(loginOutput.VerificationCodeTTL),
			},
		}
	}

	return response, nil
}

func (ah *AuthHandler) LoginConfirm(ctx context.Context, req *authpb.ConfirmRequest) (*authpb.TokensResponse, error) {
	tokensOutput, err := ah.authService.LoginConfirm(ctx, service.ConfirmInput{
		Email:            req.Email,
		VerificationCode: req.VerificationCode,
		Fingerprint:      req.Fingerprint,
	})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrUserNotFound),
			errors.Is(err, domain.ErrVerificationCodeNotFound):
			return nil, status.Error(codes.NotFound, "object is not found")
		case errors.Is(err, domain.ErrInvalidVerificationCode):
			return nil, status.Error(codes.InvalidArgument, "invalid argument")
		case errors.Is(err, domain.ErrVerificationCodeAlreadyExists):
			return nil, status.Error(codes.AlreadyExists, "object already exists")
		default:
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	// domain.ErrVerificationCodeNotFound
	// domain.ErrInvalidVerificationCode
	// domain.ErrUserNotFound
	// domain.ErrVerificationCodeAlreadyExists

	return &authpb.TokensResponse{
		AccessToken:    tokensOutput.AccessToken,
		AccessTokenTtl: durationpb.New(tokensOutput.AccessTokenTTL),
		RefreshToken:   tokensOutput.RefreshToken,
	}, nil
}

func (ah *AuthHandler) Logout(ctx context.Context, req *authpb.UserSecureRequest) (*authpb.GenericResponse, error) {
	ok, err := ah.authService.Logout(ctx, service.UserSecureInput{
		AccessToken:  req.AccessToken,
		RefreshToken: req.RefreshToken,
		Fingerprint:  req.Fingerprint,
	})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrRefreshTokenNotFound):
			return nil, status.Error(codes.NotFound, "object is not found")
		case errors.Is(err, domain.ErrInvalidAccessToken),
			errors.Is(err, domain.ErrInvalidRefreshToken):
			return nil, status.Error(codes.InvalidArgument, "invalid argument")
		case errors.Is(err, domain.ErrInvalidAction):
			return nil, status.Error(codes.Unauthenticated, "unauthenticated request")
		default:
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	// domain.ErrUnknownObjectType
	// domain.ErrInvalidTime
	// domain.ErrInvalidAccessToken
	// domain.ErrInvalidRefreshToken
	// domain.ErrInvalidID
	// domain.ErrRefreshTokenNotFound
	// domain.ErrInvalidAction
	// domain.ErrParsingObjectType
	// domain.ErrUnknownObjectType

	return &authpb.GenericResponse{
		Success: ok,
	}, nil
}

func (ah *AuthHandler) LogoutAll(ctx context.Context, req *authpb.UserSecureRequest) (*authpb.GenericResponse, error) {
	ok, err := ah.authService.LogoutAll(ctx, service.UserSecureInput{
		AccessToken:  req.AccessToken,
		RefreshToken: req.RefreshToken,
		Fingerprint:  req.Fingerprint,
	})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrRefreshTokenNotFound):
			return nil, status.Error(codes.NotFound, "object is not found")
		case errors.Is(err, domain.ErrInvalidAccessToken),
			errors.Is(err, domain.ErrInvalidRefreshToken):
			return nil, status.Error(codes.InvalidArgument, "invalid argument")
		case errors.Is(err, domain.ErrInvalidAction):
			return nil, status.Error(codes.Unauthenticated, "unauthenticated request")
		default:
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	// domain.ErrUnknownObjectType
	// domain.ErrInvalidTime
	// domain.ErrInvalidAccessToken
	// domain.ErrInvalidRefreshToken
	// domain.ErrInvalidID
	// domain.ErrRefreshTokenNotFound
	// domain.ErrInvalidAction

	return &authpb.GenericResponse{
		Success: ok,
	}, nil
}

func (ah *AuthHandler) GetSecretPhraseHint(ctx context.Context, req *authpb.EmailRequest) (*authpb.GetSecretPhraseHintResponse, error) {
	hint, err := ah.authService.GetSecretPhraseHint(ctx, req.Email)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrUserNotFound),
			errors.Is(err, domain.ErrVerificationCodeNotFound):
			return nil, status.Error(codes.NotFound, "object is not found")
		default:
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	// domain.ErrVerificationCodeNotFound
	// domain.ErrUserNotFound

	return &authpb.GetSecretPhraseHintResponse{
		SecretPhraseHint: hint,
	}, nil
}

func (ah *AuthHandler) ChangePassword(ctx context.Context, req *authpb.ChangePasswordRequest) (*authpb.VerificationCodeResponse, error) {
	verificationCodeTTL, err := ah.authService.ChangePassword(ctx, service.ChangePasswordInput{
		Email:        req.Email,
		SecretPhrase: req.SecretPhrase,
	})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrUserNotFound):
			return nil, status.Error(codes.NotFound, "object is not found")
		case errors.Is(err, domain.ErrInvalidSecretPhrase):
			return nil, status.Error(codes.InvalidArgument, "invalid argument")
		case errors.Is(err, domain.ErrVerificationCodeAlreadyExists):
			return nil, status.Error(codes.AlreadyExists, "object already exists")
		default:
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	// domain.ErrUserNotFound
	// domain.ErrInvalidSecretPhrase
	// domain.ErrVerificationCodeAlreadyExists

	return &authpb.VerificationCodeResponse{
		VerificationCodeTtl: durationpb.New(verificationCodeTTL),
	}, nil
}

func (ah *AuthHandler) ChangePasswordConfirm(ctx context.Context, req *authpb.ChangePasswordConfirmRequest) (*authpb.GenericResponse, error) {
	ok, err := ah.authService.ChangePasswordConfirm(ctx, service.ChangePasswordConfirmInput{
		Email:            req.Email,
		NewPassword:      req.NewPassword,
		VerificationCode: req.VerificationCode,
	})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrUserNotFound),
			errors.Is(err, domain.ErrRefreshTokenNotFound):
			return nil, status.Error(codes.NotFound, "object is not found")
		case errors.Is(err, domain.ErrInvalidVerificationCode):
			return nil, status.Error(codes.InvalidArgument, "invalid argument")
		default:
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	// domain.ErrUserNotFound
	// domain.ErrVerificationCodeNotFound
	// domain.ErrInvalidVerificationCode

	return &authpb.GenericResponse{
		Success: ok,
	}, nil
}

func (ah *AuthHandler) ChangePasswordWithTokens(ctx context.Context, req *authpb.ChangePasswordWithTokensRequest) (*authpb.GenericResponse, error) {
	ok, err := ah.authService.ChangePasswordWithTokens(ctx, service.ChangePasswordWithTokensInput{
		AccessToken:    req.AccessToken,
		RefreshToken:   req.RefreshToken,
		Fingerprint:    req.Fingerprint,
		OldPassword:    req.OldPassword,
		NewPassword:    req.NewPassword,
		WantsLogoutAll: req.WantsLogoutAll,
	})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrRefreshTokenNotFound),
			errors.Is(err, domain.ErrUserNotFound):
			return nil, status.Error(codes.NotFound, "object is not found")
		case errors.Is(err, domain.ErrInvalidAccessToken),
			errors.Is(err, domain.ErrInvalidRefreshToken),
			errors.Is(err, domain.ErrInvalidPassword):
			return nil, status.Error(codes.InvalidArgument, "invalid argument")
		case errors.Is(err, domain.ErrInvalidAction):
			return nil, status.Error(codes.Unauthenticated, "unauthenticated request")
		default:
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	// domain.ErrUnknownObjectType
	// domain.ErrInvalidTime
	// domain.ErrInvalidAccessToken
	// domain.ErrInvalidRefreshToken
	// domain.ErrInvalidID
	// domain.ErrRefreshTokenNotFound
	// domain.ErrInvalidAction
	// domain.ErrUserNotFound
	// domain.ErrInvalidPassword

	return &authpb.GenericResponse{
		Success: ok,
	}, nil
}

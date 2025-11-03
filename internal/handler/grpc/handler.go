package grpc

import (
	authpb "github.com/safechildhood/auth/api/grpc/auth"
	"github.com/safechildhood/auth/internal/service"
	"google.golang.org/grpc"
)

type Handler struct {
	server *grpc.Server

	service *service.Service
}

func NewHandler(server *grpc.Server, service *service.Service) *Handler {
	return &Handler{
		server:  server,
		service: service,
	}
}

func (h *Handler) Init() {
	h.initAuth()
}

func (h *Handler) initAuth() {
	authHandler := NewAuthHandler(h.service.Auth)

	authpb.RegisterAuthServiceServer(h.server, authHandler)
}

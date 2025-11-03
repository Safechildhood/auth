package handler

import (
	"net"

	"github.com/safechildhood/auth/internal/config"
	grpcHandler "github.com/safechildhood/auth/internal/handler/grpc"
	"github.com/safechildhood/auth/internal/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
)

type Handler struct {
	server *grpc.Server

	service *service.Service

	config *config.Server
}

func New(service *service.Service, config *config.Server) *Handler {
	return &Handler{
		service: service,
		config:  config,
	}
}

func (h *Handler) Init() {
	h.initGRPC()
}

func (h *Handler) initGRPC() {
	h.server = grpc.NewServer(
		grpc.Creds(insecure.NewCredentials()),
	)

	authHander := grpcHandler.NewHandler(h.server, h.service)
	authHander.Init()

	reflection.Register(h.server)
}

func (h *Handler) Start() error {
	grpcLis, err := net.Listen("tcp", h.config.Host+":"+h.config.Port)
	if err != nil {
		return err
	}

	return h.server.Serve(grpcLis)
}

func (h *Handler) Stop() {
	h.server.GracefulStop()
}

func (h *Handler) ForceStop() {
	h.server.Stop()
}

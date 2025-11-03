FROM golang:1.25.3-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -a -ldflags="-w -s -extldflags '-static'" -o main ./cmd/auth/

# FROM debian:bookworm

# WORKDIR /app
#
# COPY --from=builder /app/main .
# COPY --from=builder /app/configs ./configs/
# COPY --from=builder /app/configs ./
# COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

EXPOSE 8080

CMD ["./main"]

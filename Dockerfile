# Stage 1: Build the Go binary statically
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Download dependencies first (leverages Docker layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and build static binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o auth-cli ./cmd/cli

# Stage 2: Minimal runtime image
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/auth-cli .

# Entrypoint for interactive CLI
ENTRYPOINT ["./auth-cli"]
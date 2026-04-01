# Multi-stage build for the word game application
# Stage 1: Builder
FROM golang:1.26-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache gcc musl-dev sqlite-dev

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy application code
COPY . .

# Build the application
# Adjust the path if your main.go is in a subdirectory (e.g., ./cmd/wordgame/main.go)
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o wordgame .

# Stage 2: Runtime
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates sqlite-libs tzdata curl

# Create non-root user
RUN addgroup -g 1000 appuser && adduser -D -u 1000 -G appuser appuser

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/wordgame /app/wordgame

# Create data directory for SQLite database (mounted as volume)
RUN chmod +x /app/wordgame && mkdir -p /app/data && chown -R appuser:appuser /app

USER appuser

# Expose port (default 8080)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/healthz || exit 1

# Environment variables
ENV ADDR=:8080
ENV DB_PATH=/app/data/app.db

# Run application
CMD ["/app/wordgame"]

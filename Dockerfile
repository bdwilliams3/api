# Stage 1: Build the Go binary
FROM golang:1.26-alpine AS builder
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-s -w" -o k-api .

# Stage 2: Final minimal image (scratch — no shell, no OS package CVEs)
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
WORKDIR /app
COPY --from=builder /app/k-api /app/k-api
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/app/k-api", "-healthcheck"]
CMD ["/app/k-api"]

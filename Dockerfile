# Stage 1: Build the Go binary
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o k-api main.go

# Stage 2: Final minimal image
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/k-api .
# Run as a non-root user for security
USER 1000
EXPOSE 8080
CMD ["./k-api"]
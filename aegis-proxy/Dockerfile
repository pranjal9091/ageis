FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o aegis-gateway .

FROM alpine:latest
RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY --from=builder /app/aegis-gateway .
COPY --from=builder /app/config ./config

ENV PORT=8080
EXPOSE 8080

CMD ["./aegis-gateway"]

# -------------------------------------------------------------
# Stage 1: Build the React 19 + TypeScript Dashboard
# -------------------------------------------------------------
FROM node:20-alpine AS ui-builder
WORKDIR /app/aegis-ui
COPY aegis-ui/package*.json ./
RUN npm ci
COPY aegis-ui/ ./
RUN npm run build

# -------------------------------------------------------------
# Stage 2: Build the Golang Reverse Proxy Gateway
# -------------------------------------------------------------
FROM golang:1.22-alpine AS proxy-builder
WORKDIR /app/aegis-proxy
COPY aegis-proxy/go.mod aegis-proxy/go.sum ./
RUN go mod download
COPY aegis-proxy/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o aegis-gateway .

# -------------------------------------------------------------
# Stage 3: Unified Production Alpine Container
# -------------------------------------------------------------
FROM python:3.11-alpine

RUN apk add --no-cache nginx gettext ca-certificates bash

WORKDIR /app

# 1. Setup Python Threat Intelligence Engine
COPY aegis-intel/requirements.txt ./aegis-intel/
RUN pip install --no-cache-dir -r ./aegis-intel/requirements.txt
COPY aegis-intel/ ./aegis-intel/

# 2. Setup Go Proxy Core
COPY --from=proxy-builder /app/aegis-proxy/aegis-gateway ./aegis-proxy/
COPY aegis-proxy/config ./aegis-proxy/config

# 3. Setup React Dashboard static distribution in Nginx
COPY --from=ui-builder /app/aegis-ui/dist /usr/share/nginx/html

# 4. Copy Nginx Configuration Template & Entrypoint
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENV PORT=8080
ENV DEFAULT_UPSTREAM=https://httpbin.org
EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]

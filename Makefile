.PHONY: all start build test clean help

all: build

help:
	@echo "Aegis Zero-Trust Edge Platform"
	@echo "Usage:"
	@echo "  make start   - Boots Go Proxy (:8080), Python Intel (:5050), and React Dashboard (:5173)"
	@echo "  make build   - Compiles Go binary and builds React bundle"
	@echo "  make test    - Runs test suite across Go and Python modules"
	@echo "  make clean   - Removes build artifacts"

start:
	./start.sh

build:
	@echo "Building Aegis Go proxy..."
	cd aegis-proxy && go build -o aegis-bin .
	@echo "Building Aegis UI..."
	cd aegis-ui && npm run build
	@echo "Build successful."

test:
	@echo "Testing Python Threat Analyzer..."
	cd aegis-intel && python3 analyzer.py
	@echo "Testing Go Proxy compilation..."
	cd aegis-proxy && go vet ./...

docker-up:
	docker-compose up -d --build

docker-down:
	docker-compose down

clean:
	rm -f aegis-proxy/aegis-bin
	rm -rf aegis-ui/dist


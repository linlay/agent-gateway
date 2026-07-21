APP_NAME := agent-gateway
BINARY := bin/$(APP_NAME)
COMPOSE_FILE ?= compose.yml
CGO_ENABLED ?= 0
HEALTH_URL ?= http://127.0.0.1:11945/healthz

.PHONY: run build test fmt vet clean docker-build docker-up docker-down docker-logs docker-ps check backup deploy health

run:
	set -a; [ ! -f .env ] || . ./.env; set +a; CGO_ENABLED=$(CGO_ENABLED) go run ./cmd/agent-gateway

build:
	mkdir -p bin
	CGO_ENABLED=$(CGO_ENABLED) go build -trimpath -o $(BINARY) ./cmd/agent-gateway

test:
	CGO_ENABLED=$(CGO_ENABLED) go test ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

vet:
	CGO_ENABLED=$(CGO_ENABLED) go vet ./...

clean:
	rm -rf bin

docker-build:
	docker compose -f $(COMPOSE_FILE) build

docker-up:
	docker compose -f $(COMPOSE_FILE) up -d --build

docker-down:
	docker compose -f $(COMPOSE_FILE) down

docker-logs:
	docker compose -f $(COMPOSE_FILE) logs -f --tail=200 agent-gateway

docker-ps:
	docker compose -f $(COMPOSE_FILE) ps

check:
	docker compose -f $(COMPOSE_FILE) exec -T agent-gateway agent-gateway -check

backup:
	docker compose -f $(COMPOSE_FILE) exec -T agent-gateway sh -c 'mkdir -p /app/data/backups && exec agent-gateway -backup /app/data/backups/gateway-'$$(date +%Y%m%d%H%M%S)'.db'

deploy:
	docker compose -f $(COMPOSE_FILE) up -d --build --remove-orphans
	docker compose -f $(COMPOSE_FILE) ps

health:
	curl --fail --silent --show-error $(HEALTH_URL)

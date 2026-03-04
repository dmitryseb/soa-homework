.PHONY: generate build run db-up db-down migrate

generate:
	go generate ./...

build: generate
	go build -o bin/marketplace ./cmd/server

run:
	go run ./cmd/server

db-up:
	docker compose up -d postgres

db-down:
	docker compose down -v

migrate:
	docker compose run --rm flyway

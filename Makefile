.PHONY: generate lint test build run

generate:
	go generate ./...

lint:
	test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }
	go vet ./...

test:
	go test -race ./...

build:
	go build -o bin/server ./cmd/server

run:
	go run ./cmd/server

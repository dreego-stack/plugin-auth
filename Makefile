.PHONY: init test test-race vet

init:
	go mod download
	go mod vendor

test:
	go test -mod=vendor ./...

test-race:
	go test -mod=vendor -race ./...

vet:
	go vet -mod=vendor ./...

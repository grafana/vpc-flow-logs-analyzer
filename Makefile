BINARY := vpc-flow-logs-analyzer

.PHONY: all build test test-race vet fmt tidy clean

all: build

build:
	go build -o $(BINARY) .

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	go fmt ./...

tidy:
	go mod tidy

clean:
	rm -f $(BINARY)

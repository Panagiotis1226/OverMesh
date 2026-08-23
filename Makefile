MODULE   := github.com/panagiotis1226/overmesh
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X $(MODULE)/internal/version.Version=$(VERSION)
BINARIES := overmesh-server overmeshd overmesh overmesh-relay
TOOLS    := $(CURDIR)/.tools

.PHONY: all build test vet lint proto tools lab-up lab-verify lab-down clean

all: build

## build: compile all binaries into ./bin for the host platform
build:
	@mkdir -p bin
	@for b in $(BINARIES); do \
		echo "  building bin/$$b"; \
		go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$$b ./cmd/$$b || exit 1; \
	done

## test: run unit tests with the race detector
test:
	go test -race ./...

## vet: static analysis
vet:
	go vet ./...

## proto: regenerate Go code from proto/ (needs `make tools` once)
proto:
	$(TOOLS)/buf lint
	$(TOOLS)/buf generate

## webui: rebuild the embedded admin UI (needs node); dist/ is committed
webui:
	cd webui && npm install && npm run build

## integration: Phase 1 end-to-end test (Linux, needs sudo)
integration:
	sudo env "PATH=$(PATH)" test/integration/phase1.sh

## tools: install buf + protoc plugins into ./.tools
tools:
	GOBIN=$(TOOLS) go install github.com/bufbuild/buf/cmd/buf@v1.50.0
	GOBIN=$(TOOLS) go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.6
	GOBIN=$(TOOLS) go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1

## lab-up / lab-verify / lab-down: NAT-simulation lab (Linux, needs sudo)
lab-up:
	sudo test/lab/lab.sh up

lab-verify:
	sudo test/lab/lab.sh verify

lab-down:
	sudo test/lab/lab.sh down

clean:
	rm -rf bin dist

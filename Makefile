WORKDIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

APP := yespower-go

REVISION := $(shell git rev-parse --short=8 HEAD)
TAG := $(shell git describe --tags --exact-match $(REVISION) 2>/dev/null)

GO111MODULE ?= auto
GOFLAGS ?= -mod=vendor

LDFLAGS := -ldflags "-s -w"

TEST_TOOL := go
ifneq (, $(shell which richgo))
TEST_TOOL := richgo
endif

.PHONY: all
all: build test

.PHONY: build
build:
	$(info # #########################################################)
	$(info #)
	$(info # Building $(APP))
	$(info #)
	$(info # #########################################################)
	GOOS=linux GOARCH=amd64 go build -o yespower $(LDFLAGS) yespower.go

.PHONY: test tests
test tests:
	$(info # #########################################################)
	$(info #)
	$(info # Testing $(APP))
	$(info #)
	$(info # #########################################################)
	$(TEST_TOOL) test -v

.PHONY: bench benchmark
bench benchmark:
	$(info # #########################################################)
	$(info #)
	$(info # Benchmarking $(APP))
	$(info #)
	$(info # #########################################################)
	$(TEST_TOOL) test -bench=Yes -benchtime 4s

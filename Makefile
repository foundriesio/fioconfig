COMMIT:=$(shell git log -1 --pretty=format:%h)$(shell git diff --quiet || echo '_')

# Use linker flags to provide commit info
LDFLAGS=-ldflags "-X=github.com/foundriesio/fioconfig/internal.Commit=$(COMMIT)"

TARGETS=bin/fioconfig-linux-amd64 bin/fioconfig-linux-armv7 bin/fioconfig-linux-arm

linter:=$(shell which golangci-lint 2>/dev/null || echo $(HOME)/go/bin/golangci-lint)

build: $(TARGETS)
	@true

bin/fioconfig-linux-amd64:
bin/fioconfig-linux-armv7:
bin/fioconfig-linux-arm:
bin/fioconfig-%: FORCE
	GOOS=$(shell echo $* | cut -f1 -d\- ) \
	GOARCH=$(shell echo $* | cut -f2 -d\-) \
		go build $(LDFLAGS) -o $@ main.go

FORCE:

format:
	@gofmt -l  -w ./

check: test
	@test -z $(shell gofmt -l ./ | tee /dev/stderr) || (echo "[WARN] Fix formatting issues with 'make fmt'"; exit 1)
	@test -x $(linter) || (echo "Please install linter from https://github.com/golangci/golangci-lint/releases/tag/v1.25.1 to $(HOME)/go/bin")
	$(linter) run

test:
	go test ./... -v

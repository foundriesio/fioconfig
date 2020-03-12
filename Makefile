COMMIT:=$(shell git log -1 --pretty=format:%h)$(shell git diff --quiet || echo '_')

# Use linker flags to provide commit info
LDFLAGS=-ldflags "-X=github.com/foundriesio/schneierteard/internal.Commit=$(COMMIT)"

TARGETS=bin/schneierteard-linux-amd64 bin/schneierteard-linux-armv7 bin/schneierteard-linux-arm

build: $(TARGETS)
	@true

bin/schneierteard-linux-amd64:
bin/schneierteard-linux-armv7:
bin/schneierteard-linux-arm:
bin/schneierteard-%: FORCE
	GOOS=$(shell echo $* | cut -f1 -d\- ) \
	GOARCH=$(shell echo $* | cut -f2 -d\-) \
		go build $(LDFLAGS) -o $@ main.go

FORCE:

format:
	@gofmt -l  -w ./

check: test
	@test -z $(shell gofmt -l ./ | tee /dev/stderr) || echo "[WARN] Fix formatting issues with 'make fmt'"

test:
	go test ./... -v

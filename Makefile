build: bin/schneierteard-linux-amd64 bin/schneierteard-linux-armv7 bin/schneierteard-linux-arm

bin/schneierteard-linux-amd64:
bin/schneierteard-linux-armv7:
bin/schneierteard-linux-arm:
bin/schneierteard-%:
	GOOS=$(shell echo $* | cut -f1 -d\- ) \
	GOARCH=$(shell echo $* | cut -f2 -d\-) \
		go build $(LDFLAGS) -o $@ main.go

format:
	@gofmt -l  -w ./

check: test
	@test -z $(shell gofmt -l ./ | tee /dev/stderr) || echo "[WARN] Fix formatting issues with 'make fmt'"

test:
	go test ./internal

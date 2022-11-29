module github.com/foundriesio/fioconfig

go 1.17

require (
	github.com/ThalesIgnite/crypto11 v1.2.5
	github.com/coreos/go-systemd/v22 v22.5.0
	github.com/ethereum/go-ethereum v1.10.22
	github.com/google/uuid v1.2.0
	github.com/miekg/pkcs11 v1.0.3-0.20190429190417-a667d056470f
	github.com/pelletier/go-toml v1.8.0
	github.com/stretchr/testify v1.7.2
	github.com/urfave/cli/v2 v2.10.2
	go.mozilla.org/pkcs7 v0.0.0-20210826202110-33d05740a352
)

require (
	github.com/btcsuite/btcd v0.20.1-beta // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.2.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/godbus/dbus/v5 v5.0.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/sys v0.0.0-20220520151302-bc2c85ada10a // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/ThalesIgnite/crypto11 => github.com/foundriesio/crypto11 v0.0.0-20221104185643-b2344c63166b

replace github.com/pelletier/go-toml => github.com/foundriesio/go-toml v1.8.1-0.20200721033514-2232fec316b9

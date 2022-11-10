module github.com/foundriesio/fioconfig

go 1.17

require (
	github.com/ThalesIgnite/crypto11 v1.2.5
	github.com/ethereum/go-ethereum v1.10.15
	github.com/google/uuid v1.1.5
	github.com/miekg/pkcs11 v1.0.3-0.20190429190417-a667d056470f
	github.com/pelletier/go-toml v1.8.0
	github.com/stretchr/testify v1.7.0
	github.com/urfave/cli/v2 v2.3.0
	go.mozilla.org/pkcs7 v0.0.0-20210826202110-33d05740a352
)

require (
	github.com/btcsuite/btcd v0.20.1-beta // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.0-20190314233015-f79a8a8ca69d // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/russross/blackfriday/v2 v2.0.1 // indirect
	github.com/shurcooL/sanitized_anchor_name v1.0.0 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2 // indirect
	golang.org/x/sys v0.0.0-20210816183151-1e6c022a8912 // indirect
	gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c // indirect
)

replace github.com/ThalesIgnite/crypto11 => github.com/foundriesio/crypto11 v0.0.0-20221104185643-b2344c63166b

replace github.com/pelletier/go-toml => github.com/foundriesio/go-toml v1.8.1-0.20200721033514-2232fec316b9

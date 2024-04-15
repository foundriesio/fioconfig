module github.com/foundriesio/fioconfig

go 1.22

require (
	github.com/ThalesIgnite/crypto11 v1.2.5
	github.com/coreos/go-systemd/v22 v22.5.0
	github.com/foundriesio/go-ecies v0.3.0
	github.com/google/uuid v1.6.0
	github.com/miekg/pkcs11 v1.0.3-0.20190429190417-a667d056470f
	github.com/pelletier/go-toml v1.9.5
	github.com/stretchr/testify v1.9.0
	github.com/urfave/cli/v2 v2.27.1
	go.mozilla.org/pkcs7 v0.0.0-20210826202110-33d05740a352
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.4 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	github.com/xrash/smetrics v0.0.0-20240312152122-5f08fbb34913 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/ThalesIgnite/crypto11 => github.com/foundriesio/crypto11 v0.0.0-20221104185643-b2344c63166b

replace github.com/pelletier/go-toml => github.com/foundriesio/go-toml v1.8.1-0.20200721033514-2232fec316b9

package transport

import (
	"net/http"

	"time"

	"github.com/foundriesio/fioconfig/sotatoml"
)

func CreateClient(cfg *sotatoml.AppConfig) (*http.Client, error) {
	tlsCfg, _, err := GetTlsConfig(cfg)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg}
	return &http.Client{Timeout: time.Second * 30, Transport: transport}, nil
}

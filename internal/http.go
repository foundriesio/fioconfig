package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type httpRes struct {
	StatusCode int
	Body       []byte
	Header     http.Header
}

func (res httpRes) Json(data interface{}) error {
	return json.Unmarshal(res.Body, data)
}

func (res httpRes) String() string {
	return string(res.Body)
}

func readResponse(r *http.Response) (*httpRes, error) {
	defer r.Body.Close()
	res := &httpRes{
		StatusCode: r.StatusCode,
		Header:     r.Header,
	}
	var err error
	res.Body, err = io.ReadAll(r.Body)
	if err != nil {
		return res, fmt.Errorf("Unable to read response from %s: %w", r.Request.URL, err)
	}
	return res, nil
}

func httpGet(client *http.Client, url string, headers map[string]string) (*httpRes, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("User-Agent", "fioconfig-client/2")
	req.Close = true

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Unable to get: %s - %w", url, err)
	}
	return readResponse(res)
}

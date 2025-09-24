package transport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type HttpRes struct {
	StatusCode int
	Body       []byte
	Header     http.Header
}

func (res HttpRes) Json(data any) error {
	return json.Unmarshal(res.Body, data)
}

func (res HttpRes) String() string {
	return string(res.Body)
}

func HttpGet(client *http.Client, url string, headers map[string]string) (*HttpRes, error) {
	return HttpDo(client, http.MethodGet, url, headers, nil)
}

func HttpPatch(client *http.Client, url string, data any) (*HttpRes, error) {
	return HttpDo(client, http.MethodPatch, url, nil, data)
}

func HttpPost(client *http.Client, url string, data any) (*HttpRes, error) {
	return HttpDo(client, http.MethodPost, url, nil, data)
}

func readResponse(r *http.Response) (*HttpRes, error) {
	defer r.Body.Close()
	res := &HttpRes{
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

func httpDoOnce(client *http.Client, method, url string, headers map[string]string, data any) (*HttpRes, error) {
	var dataBytes []byte
	if data != nil {
		var ok bool
		dataBytes, ok = data.([]byte)
		if !ok {
			// If data is not a byte array - assuming we should marshal as JSON
			var err error
			dataBytes, err = json.Marshal(data)
			if err != nil {
				return nil, err
			}
		}
	}
	req, err := http.NewRequest(method, url, bytes.NewBuffer(dataBytes))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Add(k, v)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Add("User-Agent", "fioconfig-client/2")
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Add("Content-Type", "application/json")
	}
	req.Close = true

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Unable to %s: %s - %w", method, url, err)
	}
	return readResponse(res)
}

// HttpDo performs an HTTP request with retries for transient errors. The `data`
// parameter can be:
// - nil: No body will be sent
// - []byte: The body will be sent as is
// - a struct to be marshaled as JSON
func HttpDo(client *http.Client, method, url string, headers map[string]string, data any) (*HttpRes, error) {
	var err error
	var res *HttpRes
	for _, delay := range []int{0, 1, 2, 5, 13, 30} {
		if delay != 0 {
			log.Printf("HTTP %s to %s failed, trying again in %d seconds", url, method, delay)
			time.Sleep(time.Second * time.Duration(delay))
		}
		res, err = httpDoOnce(client, method, url, headers, data)
		if err == nil && res.StatusCode != 0 && res.StatusCode < 500 {
			break
		}
	}
	return res, err
}

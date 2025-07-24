package fiotest

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/foundriesio/fioconfig/transport"
)

type Api struct {
	client  *http.Client
	baseUrl string
}

type Test struct {
	client *http.Client
	url    string
}

func NewApi(client *http.Client, fiotestUrl string) *Api {
	return &Api{client: client, baseUrl: fiotestUrl}
}

func (a Api) Create(name, testId string) (*Test, error) {
	// Hard-coded to group all tests by the same Target in the backend
	headers := map[string]string{"x-ats-target": "fiocofig-action"}

	type testbody struct {
		Name   string `json:"name"`
		TestId string `json:"test-id"`
	}
	body := testbody{Name: name, TestId: testId}

	res, err := transport.HttpDo(a.client, http.MethodPost, a.baseUrl, headers, body)
	if err != nil {
		return nil, err
	} else if res.StatusCode != 201 {
		return nil, fmt.Errorf("Unable to create test record: HTTP_%d - %s", res.StatusCode, res.String())
	}

	return &Test{client: a.client, url: a.baseUrl + "/" + res.String()}, nil
}

func (t Test) Complete(result Result) error {
	// Complete the test through the API
	type trbody struct {
		Status    string   `json:"status"`
		Details   string   `json:"details"`
		Artifacts []string `json:"artifacts"`
	}
	tr := trbody{
		Status:  result.Status,
		Details: result.Details,
	}
	for _, artifact := range result.Artifacts {
		tr.Artifacts = append(tr.Artifacts, artifact.Name())
	}

	res, err := transport.HttpDo(t.client, http.MethodPut, t.url, nil, tr)
	if err != nil {
		return err
	} else if res.StatusCode != 200 {
		return fmt.Errorf("Unable to complete test record: HTTP_%d - %s", res.StatusCode, res.String())
	}

	// The completion operation returns signed URLs for us to upload artifacts to
	type resultResp struct {
		Url         string `json:"url"`
		ContentType string `json:"content-type"`
	}
	var rr map[string]resultResp
	if err := json.Unmarshal(res.Body, &rr); err != nil {
		return err
	}

	for _, artifact := range result.Artifacts {
		name := artifact.Name()
		url := rr[name].Url

		uploadClient := http.DefaultClient
		if strings.HasPrefix(url, t.url) {
			uploadClient = t.client
		}
		log.Printf("Uploading artifact: %s", name)
		headers := map[string]string{"Content-Type": rr[name].ContentType}
		res, err = transport.HttpDo(uploadClient, http.MethodPut, url, headers, artifact.Content())
		if err != nil {
			return err
		} else if res.StatusCode != 200 {
			return fmt.Errorf("Unable to upload test output: HTTP_%d - %s", res.StatusCode, res.String())
		}
	}
	return nil
}

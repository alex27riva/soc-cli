/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func GetRaw(url string, headers map[string]string) (body []byte, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	return body, nil
}

func HTTPGetJSON(url string, headers map[string]string, target any) (sc int, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, fmt.Errorf("error creating request: %w", err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("error reading response body: %w", err)
	}

	err = json.Unmarshal(body, target)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("error unmarshalling JSON response: %w", err)
	}

	return resp.StatusCode, nil
}

func HTTPPostJSON(url string, headers map[string]string, body any, target interface{}) error {
	// Marshal the body into JSON
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("error marshalling request body: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	// Set headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	// Set Content-Type header to application/json
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	bodyResp, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %w", err)
	}

	err = json.Unmarshal(bodyResp, target)
	if err != nil {
		return fmt.Errorf("error unmarshalling JSON response: %w", err)
	}

	return nil
}

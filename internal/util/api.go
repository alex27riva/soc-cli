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
	"log"
	"net/http"
	"os"
	"strconv"
)

var debug bool

func init() {
	// Check if SOC_DEBUG is set and enable debug mode if it is
	if val, exists := os.LookupEnv("SOC_DEBUG"); exists {
		debug, _ = strconv.ParseBool(val)
	}
}

func MakeGETRequest(url string, headers map[string]string, target interface{}) (sc int, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, fmt.Errorf("error creating request: %w", err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Log request details if debug is enabled
	if debug {
		log.Printf("Making API request to URL: %s", url)
		for key, value := range headers {
			log.Printf("Header: %s = %s", key, value)
		}
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

	if debug {
		log.Printf("Response body: %s", string(body))
	}

	err = json.Unmarshal(body, target)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("error unmarshalling JSON response: %w", err)
	}

	return resp.StatusCode, nil
}

func MakePOSTRequest(url string, headers map[string]string, body interface{}, target interface{}) error {
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

	// Log request details if debug is enabled
	if debug {
		log.Printf("Making API request to URL: %s", url)
		for key, value := range headers {
			log.Printf("Header: %s = %s", key, value)
		}
		log.Printf("Request body: %s", string(jsonBody))
	}

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

	if debug {
		log.Printf("Response body: %s", string(bodyResp))
	}

	err = json.Unmarshal(bodyResp, target)
	if err != nil {
		return fmt.Errorf("error unmarshalling JSON response: %w", err)
	}

	return nil
}

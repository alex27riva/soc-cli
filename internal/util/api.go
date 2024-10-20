/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package util

import (
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

func MakeAPIRequest(url string, headers map[string]string, target interface{}) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
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
		return fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %w", err)
	}

	if debug {
		log.Printf("Response body: %s", string(body))
	}

	err = json.Unmarshal(body, target)
	if err != nil {
		return fmt.Errorf("error unmarshalling JSON response: %w", err)
	}

	return nil
}

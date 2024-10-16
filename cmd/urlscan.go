/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log"
	"net/http"
	"time"
)

// urlScanResult represents a simplified result from URLscan.io
type urlScanResult struct {
	Page struct {
		URL     string `json:"url"`
		Domain  string `json:"domain"`
		Country string `json:"country"`
	} `json:"page"`
	Verdict struct {
		Malicious bool `json:"malicious"`
	} `json:"verdicts"`
}

// submitURLScan submits a URL for scanning
func submitURLScan(url string) (string, error) {
	apiKey := viper.GetString("urlscan_api_key")
	if apiKey == "" {
		return "", fmt.Errorf("API key is missing! Please set the urlscan_api_key in config.yaml file")
	}

	apiUrl := "https://urlscan.io/api/v1/scan/"
	requestBody, err := json.Marshal(map[string]string{"url": url})
	if err != nil {
		return "", fmt.Errorf("failed to create request body: %v", err)
	}

	req, err := http.NewRequest("POST", apiUrl, bytes.NewBuffer(requestBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("API-Key", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to submit URL scan request: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	// Extract the scan ID to check for the scan status
	scanID, ok := result["uuid"].(string)
	if !ok {
		return "", fmt.Errorf("failed to get scan ID from response")
	}

	return scanID, nil
}

// fetchURLScanResult fetches the results of a URL scan
func fetchURLScanResult(scanID string) (*urlScanResult, error) {
	apiUrl := fmt.Sprintf("https://urlscan.io/api/v1/result/%s/", scanID)

	// Polling for scan results
	for i := 0; i < 10; i++ {
		resp, err := http.Get(apiUrl)
		if err != nil {
			return nil, fmt.Errorf("failed to get scan results: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			// Scan still in progress, wait and retry
			time.Sleep(5 * time.Second)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}

		// Parse the response body
		var scanResult urlScanResult
		if err := json.NewDecoder(resp.Body).Decode(&scanResult); err != nil {
			return nil, fmt.Errorf("failed to parse scan result: %v", err)
		}

		return &scanResult, nil
	}

	return nil, fmt.Errorf("scan result not available after multiple attempts")
}

// urlScanCmd represents the URL scanning command
var urlScanCmd = &cobra.Command{
	Use:   "urlscan [url]",
	Short: "Submit a URL for malware scanning and fetch the results",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		url := args[0]

		// Submit the URL for scanning
		scanID, err := submitURLScan(url)
		if err != nil {
			log.Fatalf("Error submitting URL for scan: %v", err)
		}

		fmt.Println("URL submitted successfully. Awaiting results...")

		// Fetch the scan results
		scanResult, err := fetchURLScanResult(scanID)
		if err != nil {
			log.Fatalf("Error retrieving scan results: %v", err)
		}

		// Print the scan results
		fmt.Printf("Scan Results for URL: %s\n", scanResult.Page.URL)
		fmt.Printf("Domain: %s\n", scanResult.Page.Domain)
		fmt.Printf("Country: %s\n", scanResult.Page.Country)
		if scanResult.Verdict.Malicious {
			fmt.Println("Verdict: MALICIOUS")
		} else {
			fmt.Println("Verdict: SAFE")
		}
	},
}

func init() {
	rootCmd.AddCommand(urlScanCmd)
}

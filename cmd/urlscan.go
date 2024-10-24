/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log"
	"net/http"
	"soc-cli/internal/util"
	"time"
)

var defautVisibility = "private" // public, unlisted or private

const (
	urlscanScanApi   = "https://urlscan.io/api/v1/scan/"
	urlscanResultApi = "https://urlscan.io/api/v1/result/%s/"
)

type urlScanResult struct {
	Page struct {
		URL     string `json:"url"`
		Domain  string `json:"domain"`
		Country string `json:"country"`
		IP      string `json:"ip"`
	} `json:"page"`
	Task struct {
		ReportURL string `json:"reportURL"`
	}
	Verdict struct {
		Malicious bool `json:"malicious"`
	} `json:"verdicts"`
}

// submitURLScan submits a URL for scanning
func submitURLScan(url string) (string, error) {
	apiKey := viper.GetString("api_keys.urlscan.api_key")
	if apiKey == "" {
		return "", fmt.Errorf("API key is missing! Please set the urlscan api_key in config.yaml file")
	}

	requestBody := map[string]string{"url": url, "visibility": defautVisibility}

	var result map[string]interface{}

	err := util.MakePOSTRequest(urlscanScanApi, map[string]string{"API-Key": apiKey}, requestBody, &result)

	if err != nil {
		return "", fmt.Errorf("failed to submit URL scan request: %v", err)
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
	apiUrl := fmt.Sprintf(urlscanResultApi, scanID)

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

func displayResults(scanResult urlScanResult) {
	fmt.Printf("Scan Results for URL: %s\n", scanResult.Page.URL)
	fmt.Printf("Domain: %s\n", scanResult.Page.Domain)
	fmt.Printf("Country: %s\n", scanResult.Page.Country)
	fmt.Printf("IP: %s\n", scanResult.Page.IP)
	fmt.Printf("Link: %s\n", scanResult.Task.ReportURL)
	if scanResult.Verdict.Malicious {
		fmt.Println("Verdict: " + color.RedString("MALICIOUS"))
	} else {
		fmt.Println("Verdict: " + color.GreenString("SAFE"))
	}

}

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

		color.Blue("URL submitted successfully. Awaiting results...")

		// Fetch the scan results
		scanResult, err := fetchURLScanResult(scanID)
		if err != nil {
			log.Fatalf("Error retrieving scan results: %v", err)
		}
		displayResults(*scanResult)

	},
}

func init() {
	rootCmd.AddCommand(urlScanCmd)
}

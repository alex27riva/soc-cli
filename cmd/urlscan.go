/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/alex27riva/soc-cli/internal/logic"
	"github.com/alex27riva/soc-cli/internal/util"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"resty.dev/v3"
)

var defangFlag bool
var visibility string

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
		Title   string `json:"title"`
	} `json:"page"`
	Task struct {
		ReportURL string `json:"reportURL"`
	}
	Verdict struct {
		Malicious bool `json:"malicious"`
	} `json:"verdicts"`
}

// submitURLScan submits a URL for scanning
func submitURLScan(url string, visibility string) (string, error) {
	apiKey := viper.GetString("api_keys.urlscan.api_key")
	if apiKey == "" {
		return "", fmt.Errorf("API key is missing! Please set the urlscan api_key in config.yaml file")
	}

	headers := map[string]string{"API-Key": apiKey}
	requestBody := map[string]string{"url": url, "visibility": visibility}

	var result map[string]any

	client := resty.New()
	defer client.Close()

	_, err := client.R().
		SetHeaders(headers).
		SetBody(requestBody).
		SetResult(&result).
		Post(urlscanScanApi)
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
	isMalicious := scanResult.Verdict.Malicious
	domain := scanResult.Page.Domain
	scannedUrl := scanResult.Page.URL

	if isMalicious || defangFlag {

		scannedUrl = logic.DefangURL(scannedUrl)
		domain = logic.DefangURL(domain)
	}

	util.PrintEntry("Scan Results for URL", scannedUrl)
	util.PrintEntry("Domain", domain)

	util.PrintEntry("Title", scanResult.Page.Title)

	util.PrintEntry("IP", scanResult.Page.IP)
	util.PrintEntry("Country", scanResult.Page.Country)
	util.PrintEntry("Link", scanResult.Task.ReportURL)
	if isMalicious {
		util.PrintEntry("Verdict", color.RedString("MALICIOUS"))
	} else {
		util.PrintEntry("Verdict", color.GreenString("SAFE"))
	}

}

var validVisibility = map[string]bool{"public": true, "unlisted": true, "private": true}

var urlScanCmd = &cobra.Command{
	Use:     "url-scan [url]",
	Aliases: []string{"urlscan"},
	Short:   "Submit a URL to urlscan.io and retrieve the scan results",
	Args:    cobra.ExactArgs(1),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if !validVisibility[visibility] {
			return fmt.Errorf("invalid visibility: %s (must be public, unlisted, or private)", visibility)
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		url := args[0]

		// Submit the URL for scanning
		scanID, err := submitURLScan(url, visibility)
		if err != nil {
			log.Fatalf("Error submitting URL for scan: %v", err)
		}

		util.PrintSuccess("URL submitted successfully.")
		util.PrintHeader("Awaiting results...")

		// Fetch the scan results
		scanResult, err := fetchURLScanResult(scanID)
		if err != nil {
			log.Fatalf("Error retrieving scan results: %v", err)
		}
		displayResults(*scanResult)

	},
}

func init() {
	urlScanCmd.Flags().BoolVar(&defangFlag, "defang", false, "Defang the URL")
	urlScanCmd.Flags().StringVar(&visibility, "visibility", "private", "Visibility of the scan (public, unlisted, or private)")
	rootCmd.AddCommand(urlScanCmd)
}

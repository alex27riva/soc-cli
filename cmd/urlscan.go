/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
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
var urlscanDebug bool

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

	slog.Debug("submitting scan", "url", url, "visibility", visibility, "apiKeyLen", len(apiKey))

	resp, err := client.R().
		SetHeaders(headers).
		SetBody(requestBody).
		SetResult(&result).
		Post(urlscanScanApi)
	if err != nil {
		return "", fmt.Errorf("failed to submit URL scan request: %v", err)
	}

	slog.Debug("submit response", "status", resp.StatusCode(), "body", resp.String())

	if resp.StatusCode() != http.StatusOK {
		body := resp.String()
		return "", fmt.Errorf("submit failed with status %d: %s", resp.StatusCode(), body)
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
	apiKey := viper.GetString("api_keys.urlscan.api_key")
	apiUrl := fmt.Sprintf(urlscanResultApi, scanID)

	client := resty.New()
	defer client.Close()

	slog.Debug("polling results", "url", apiUrl)

	for i := range 10 {
		var scanResult urlScanResult

		resp, err := client.R().
			SetHeader("API-Key", apiKey).
			SetResult(&scanResult).
			Get(apiUrl)
		if err != nil {
			return nil, fmt.Errorf("failed to get scan results: %v", err)
		}

		slog.Debug("poll attempt", "attempt", i+1, "status", resp.StatusCode())

		if resp.StatusCode() == http.StatusNotFound {
			time.Sleep(5 * time.Second)
			continue
		}

		if resp.StatusCode() != http.StatusOK {
			return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode(), resp.String())
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
		if urlscanDebug {
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
		}

		url := args[0]

		scanID, err := submitURLScan(url, visibility)
		if err != nil {
			slog.Error("submitting URL for scan", "error", err)
			os.Exit(1)
		}

		util.PrintSuccess("URL submitted successfully.")
		util.PrintHeader("Awaiting results...")

		scanResult, err := fetchURLScanResult(scanID)
		if err != nil {
			slog.Error("retrieving scan results", "error", err)
			os.Exit(1)
		}
		displayResults(*scanResult)
	},
}

func init() {
	urlScanCmd.Flags().BoolVar(&defangFlag, "defang", false, "Defang the URL")
	urlScanCmd.Flags().StringVar(&visibility, "visibility", "private", "Visibility of the scan (public, unlisted, or private)")
	urlScanCmd.Flags().BoolVar(&urlscanDebug, "debug", false, "Enable debug logging for requests and responses")
	rootCmd.AddCommand(urlScanCmd)
}

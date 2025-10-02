/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package apis

import (
	"fmt"
	"log"
	"net"

	"resty.dev/v3"
)

const (
	abuseIPBaseURL = "https://api.abuseipdb.com/api/v2"
	maxAgeDays     = 90
)

type AbuseIPDBResponse struct {
	Data struct {
		IPAddress            string   `json:"ipAddress"`
		IsPublic             bool     `json:"isPublic"`
		IPVersion            int      `json:"ipVersion"`
		IsWhitelisted        bool     `json:"isWhitelisted"`
		AbuseConfidenceScore int      `json:"abuseConfidenceScore"`
		CountryCode          string   `json:"countryCode"`
		UsageType            string   `json:"usageType"`
		ISP                  string   `json:"isp"`
		Domain               string   `json:"domain"`
		Hostnames            []string `json:"hostnames"`
		TotalReports         int      `json:"totalReports"`
		LastReportedAt       string   `json:"lastReportedAt"`
		Reports              []struct {
			ReporterID      int    `json:"reporterId"`
			ReporterCountry string `json:"reporterCountryCode"`
			ReportedAt      string `json:"reportedAt"`
			Comment         string `json:"comment"`
		} `json:"reports"`
	} `json:"data"`
}

// getAbuseIPDBInfo fetches data from AbuseIPDB for a specific IP address
func GetAbuseIPDBInfo(ip net.IP, apiKey string) *AbuseIPDBResponse {
	client := resty.New()
	defer client.Close()

	client.SetBaseURL(abuseIPBaseURL)

	headers := map[string]string{
		"Key":    apiKey,
		"Accept": "application/json",
	}

	params := map[string]string{
		"ipAddress":    ip.String(),
		"maxAgeInDays": fmt.Sprint(maxAgeDays),
		"verbose":      "",
	}

	result := &AbuseIPDBResponse{}

	_, err := client.R().
		SetHeaders(headers).
		SetQueryParams(params).
		SetResult(result).
		Get("/check")
	if err != nil {
		log.Fatalf("Error fetching AbuseIPDB info: %v", err)
	}

	return result
}

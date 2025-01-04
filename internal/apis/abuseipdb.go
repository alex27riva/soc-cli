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
	"soc-cli/internal/util"
)

const abuseAPIURL = "https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90&verbose"

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
	apiUrl := fmt.Sprintf(abuseAPIURL, ip.String())

	headers := map[string]string{
		"Key":    apiKey,
		"Accept": "application/json",
	}

	var data AbuseIPDBResponse

	_, err := util.MakeGETRequest(apiUrl, headers, &data)
	if err != nil {
		log.Fatalf("Error fetching AbuseIPDB info: %v", err)
	}

	return &data
}

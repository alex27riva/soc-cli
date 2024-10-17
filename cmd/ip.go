/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	greyNoiseAPIURL = "https://api.greynoise.io/v3/community/%s"
	ipInfoAPIURL    = "https://ipinfo.io/%s?token=%s"
	abuseAPIURL     = "https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90"
)

type ipInfo struct {
	IP       string `json:"ip"`
	Country  string `json:"country"`
	Hostname string `json:"hostname"`
	Org      string `json:"org"`
}

type greyNoiseInfo struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	Riot           bool   `json:"riot"`
	Classification string `json:"classification"`
	Name           string `json:"name"`
	Link           string `json:"link"`
}

type abuseIPDBResponse struct {
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
			ReporterCountry string `json:"reporterCountry"`
			ReportedAt      string `json:"reportedAt"`
			Comment         string `json:"comment"`
		} `json:"reports"`
	} `json:"data"`
}

// Get threat intelligence from GreyNoise API
func getGreyNoiseData(ip string, apiKey string) *greyNoiseInfo {
	apiUrl := fmt.Sprintf(greyNoiseAPIURL, ip)

	headers := map[string]string{
		"key": apiKey,
	}

	var greyNoiseData greyNoiseInfo

	err := MakeAPIRequest(apiUrl, headers, &greyNoiseData)
	if err != nil {
		log.Fatalf("Error fetching AbuseIPDB info: %v", err)
	}

	return &greyNoiseData
}

func getIPInfo(ip string, apiKey string) *ipInfo {
	apiUrl := fmt.Sprintf(ipInfoAPIURL, ip, apiKey)

	var info ipInfo

	err := MakeAPIRequest(apiUrl, nil, &info)
	if err != nil {
		log.Fatalf("Error fetching IP info: %v", err)
	}

	return &info
}

// getAbuseIPDBInfo fetches data from AbuseIPDB for a specific IP address
func getAbuseIPDBInfo(ip string, apiKey string) *abuseIPDBResponse {
	apiUrl := fmt.Sprintf(abuseAPIURL, ip)

	headers := map[string]string{
		"Key":    apiKey,
		"Accept": "application/json",
	}

	var data abuseIPDBResponse

	err := MakeAPIRequest(apiUrl, headers, &data)
	if err != nil {
		log.Fatalf("Error fetching AbuseIPDB info: %v", err)
	}

	return &data
}

func analyzeIP(ip string) {

	// Validate provided IP address
	if IPRegex.MatchString(ip) {
		if RFC1918Regex.MatchString(ip) {
			fmt.Printf("The IP provided %s is a RFC1918 bogus IP address.\n", ip)
			os.Exit(0)
		} else if ip == "127.0.0.1" {
			fmt.Printf("The IP provided %s is a loopback IP address.\n", ip)
			os.Exit(0)
		}
	} else {
		log.Fatalf("The IP provided %s is not a valid IPv4 address.\n", ip)
	}

	greyNoiseApiKey := viper.GetString("api_keys.greynoise.api_key")
	if greyNoiseApiKey == "" {
		log.Println("GreyNoise API key is missing! Please set the greynoise api_key in config.yaml file")
	}

	ipInfoApiKey := viper.GetString("api_keys.ipinfo.api_key")
	if ipInfoApiKey == "" {
		log.Println("API key is missing! Please set the ipinfo_api_key in config.yaml file")
	}

	abuseIPDBApiKey := viper.GetString("api_keys.abuseipdb.api_key")
	if abuseIPDBApiKey == "" {
		log.Println("API key is missing! Please set the ipinfo_api_key in config.yaml file")
	}

	// Fetch IpInfo api
	ipInfoData := getIPInfo(ip, ipInfoApiKey)

	// Fetch GreyNoise threat intelligence
	greyNoiseData := getGreyNoiseData(ip, greyNoiseApiKey)

	abuseIPDBData := getAbuseIPDBInfo(ip, abuseIPDBApiKey)

	// Print the IP information
	fmt.Println(Blue + "IP information from IPInfo" + Reset)
	fmt.Printf("IP: %s\nHostname: %s\nOrg: %s\nCountry: %s\n",
		ipInfoData.IP, ipInfoData.Hostname, ipInfoData.Org, ipInfoData.Country)

	if greyNoiseData != nil {
		fmt.Println(Blue + "\nGreyNoise Threat Intelligence" + Reset)

		classification := greyNoiseData.Classification
		if classification == "malicious" {
			classification = fmt.Sprintf("%s%s%s", Red, classification, Reset)
		} else if classification == "benign" {
			classification = fmt.Sprintf("%s%s%s", Green, classification, Reset)
		}

		fmt.Printf("Noise: %v\nRiot: %v\nClassification: %s\nName: %s\nLink: %s\n",
			greyNoiseData.Noise, greyNoiseData.Riot, classification, greyNoiseData.Name, greyNoiseData.Link)
	}

	if abuseIPDBData != nil {
		fmt.Println(Blue + "\nAbuseIPDB report" + Reset)

		// Print AbuseIPDB info
		fmt.Printf("AbuseIPDB Data for IP: %s\n", ip)
		fmt.Printf("Abuse Confidence Score: %d\n", abuseIPDBData.Data.AbuseConfidenceScore)
		fmt.Printf("Total Reports: %d\n", abuseIPDBData.Data.TotalReports)
		fmt.Printf("Last Reported At: %s\n", abuseIPDBData.Data.LastReportedAt)

		// Print the individual reports if available
		if len(abuseIPDBData.Data.Reports) > 0 {
			fmt.Println("\nReports:")
			for _, report := range abuseIPDBData.Data.Reports {
				fmt.Printf("Reported By: %s\nReported At: %s\nComment: %s\n",
					report.ReporterCountry, report.ReportedAt, report.Comment)
			}
		} else {
			fmt.Println("No reports found for this IP.")
		}

	}

}

var ipCmd = &cobra.Command{
	Use:   "ip [ipv4]",
	Short: "Analyze an IP address for geolocation, ASN, and threat status",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ip := args[0]
		analyzeIP(ip)
	},
}

func init() {
	rootCmd.AddCommand(ipCmd)
}

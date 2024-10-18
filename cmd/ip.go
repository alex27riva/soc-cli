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
	"soc-cli/internal/apis"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

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
	ipInfoData := apis.GetIPInfo(ip, ipInfoApiKey)

	// Fetch GreyNoise threat intelligence
	greyNoiseData := apis.GetGreyNoiseData(ip, greyNoiseApiKey)

	abuseIPDBData := apis.GetAbuseIPDBInfo(ip, abuseIPDBApiKey)

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

/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log"
	"os"
	"soc-cli/internal/apis"
	"soc-cli/internal/util"
)

var reportLimit = 3
var reportMaxLen = 40

func analyzeIP(ip string) {

	// Validate provided IP address
	if util.IPRegex.MatchString(ip) {
		if util.RFC1918Regex.MatchString(ip) {
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
		log.Println("API key is missing! Please set the ipinfo api_key in config.yaml file")
	}

	abuseIPDBApiKey := viper.GetString("api_keys.abuseipdb.api_key")
	if abuseIPDBApiKey == "" {
		log.Println("API key is missing! Please set the abuseipdb api_key in config.yaml file")
	}

	// Fetch IpInfo api
	ipInfoData := apis.GetIPInfo(ip, ipInfoApiKey)

	// Fetch GreyNoise threat intelligence
	greyNoiseData := apis.GetGreyNoiseData(ip, greyNoiseApiKey)

	abuseIPDBData := apis.GetAbuseIPDBInfo(ip, abuseIPDBApiKey)

	// Print the IP information
	color.Blue("IP information from IPInfo")
	fmt.Printf("IP: %s\nHostname: %s\nOrg: %s\nCountry: %s\n",
		ipInfoData.IP, ipInfoData.Hostname, ipInfoData.Org, ipInfoData.Country)

	if greyNoiseData != nil {
		color.Blue("\nGreyNoise Threat Intelligence")

		classification := greyNoiseData.Classification
		if classification == "malicious" {
			classification = color.RedString(classification)
		} else if classification == "benign" {
			classification = color.GreenString(classification)
		}

		fmt.Printf("Noise: %v\nRiot: %v\nClassification: %s\nName: %s\nLink: %s\n",
			greyNoiseData.Noise, greyNoiseData.Riot, classification, greyNoiseData.Name, greyNoiseData.Link)
	}

	if abuseIPDBData != nil {
		color.Blue("\nAbuseIPDB report")

		// Print AbuseIPDB info
		fmt.Printf("Abuse Confidence Score: %d\n", abuseIPDBData.Data.AbuseConfidenceScore)
		fmt.Printf("Total Reports: %d\n", abuseIPDBData.Data.TotalReports)
		fmt.Printf("Last Reported At: %s\n", abuseIPDBData.Data.LastReportedAt)

		// Print the individual reports if available
		if len(abuseIPDBData.Data.Reports) > 0 {
			fmt.Println("Reports:")
			headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
			columnFmt := color.New(color.FgYellow).SprintfFunc()

			tbl := table.New("Date", "Country", "Comment")
			tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

			for index, report := range abuseIPDBData.Data.Reports {
				if index > reportLimit {
					break
				}
				humanTime, _ := util.HumanReadableDate(report.ReportedAt)
				tbl.AddRow(humanTime, report.ReporterCountry, util.ShortStr(report.Comment, reportMaxLen))
			}
			tbl.Print()

		}

	} else {
		fmt.Println("No reports found for this IP.")
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

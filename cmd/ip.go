/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"fmt"
	"log"
	"net"
	"os"
	"soc-cli/internal/apis"
	"soc-cli/internal/util"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var reportLimit = 3
var reportMaxLen int

func checkInput(input string) {
	ip := net.ParseIP(input)
	if ip == nil {
		color.Red("Invalid IP address.")
		os.Exit(1)
	}

	// Validate provided IP address
	switch {
	case ip.IsPrivate():
		color.Red("The IP %s is a RFC1918 bogus IP address.\n", ip)
		os.Exit(0)
	case ip.IsLoopback():
		color.Red("The IP %s is a loopback IP address.\n", ip)
		os.Exit(0)
	case ip.IsMulticast():
		color.Red("The IP %s is a multicast IP address.\n", ip)
		os.Exit(0)
	case ip.To16() != nil && ip.To4() == nil:
		color.Red("IPv6 addresses are not supported yet.")
		os.Exit(0)
	}

	analyzeIP(ip)
}

func analyzeIP(ip net.IP) {

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
			classification = color.RedString(strings.ToUpper(classification))
		} else if classification == "benign" {
			classification = color.GreenString(strings.ToUpper(classification))
		}

		fmt.Printf("Noise: %v\nRiot: %v\nClassification: %s\nName: %s\nLink: %s\n",
			greyNoiseData.Noise, greyNoiseData.Riot, classification, greyNoiseData.Name, greyNoiseData.Link)
	}

	if abuseIPDBData != nil {
		color.Blue("\nAbuseIPDB report")
		if abuseIPDBData.Data.TotalReports == 0 {
			fmt.Println("No reports found for this IP address")
			return
		}
		// Parse date from string
		lastReportDate, _ := time.Parse(time.RFC3339, abuseIPDBData.Data.LastReportedAt)

		// Print AbuseIPDB info
		fmt.Printf("Abuse Confidence Score: %d\n", abuseIPDBData.Data.AbuseConfidenceScore)
		fmt.Printf("Total Reports: %d\n", abuseIPDBData.Data.TotalReports)
		fmt.Printf("Last Reported At: %s\n", lastReportDate.Format("Monday, January 2, 2006"))

		// Print the individual reports if available
		if len(abuseIPDBData.Data.Reports) > 0 {
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
		color.Red("An error has occured.")
		os.Exit(1)
	}

}

var ipCmd = &cobra.Command{
	Use:   "ip [ipv4]",
	Short: "Analyze an IP address for geolocation, ASN, and threat status",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		input := args[0]
		checkInput(input)
	},
}

func init() {
	ipCmd.Flags().IntVarP(&reportMaxLen, "length", "l", 50, "AbuseIPDB report max length")
	rootCmd.AddCommand(ipCmd)
}

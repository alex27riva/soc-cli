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
	"net"
	"os"
	"soc-cli/internal/apis"
	"soc-cli/internal/util"
	"strings"
	"time"
)

const (
	reportLimit         = 3
	defaultReportMaxLen = 100
	greyNoiseAPIKeyMsg  = "GreyNoise API key is missing! Please set the greynoise api_key in config.yaml file."
	ipInfoAPIKeyMsg     = "IPInfo API key is missing! Please set the ipinfo api_key in config.yaml file."
	abuseIPDBAPIKeyMsg  = "AbuseIPDB API key is missing! Please set the abuseipdb api_key in config.yaml file."
)

var reportMaxLen int

func checkInput(input string) error {
	ip := net.ParseIP(input)
	if ip == nil {
		color.Red("Invalid IP address.")
		os.Exit(1)
	}

	// Validate provided IP address
	switch {
	case ip.IsPrivate():
		return fmt.Errorf("the IP %s is a RFC1918 bogus IP address", ip)
	case ip.IsLoopback():
		return fmt.Errorf("the IP %s is a loopback IP address", ip)
	case ip.IsMulticast():
		return fmt.Errorf("the IP %s is a multicast IP address", ip)
	case ip.To16() != nil && ip.To4() == nil:
		return fmt.Errorf("IPv6 addresses are not supported yet")
	}

	analyzeIP(ip)
	return nil
}

func checkAPIKeys() []string {
	var missingKeys []string
	if viper.GetString("api_keys.greynoise.api_key") == "" {
		missingKeys = append(missingKeys, greyNoiseAPIKeyMsg)
	}
	if viper.GetString("api_keys.ipinfo.api_key") == "" {
		missingKeys = append(missingKeys, ipInfoAPIKeyMsg)
	}
	if viper.GetString("api_keys.abuseipdb.api_key") == "" {
		missingKeys = append(missingKeys, abuseIPDBAPIKeyMsg)
	}
	return missingKeys
}

func analyzeIP(ip net.IP) {
	missingKeys := checkAPIKeys()
	if len(missingKeys) > 0 {
		for _, msg := range missingKeys {
			color.Yellow(msg)
		}
	}

	// Fetch IP information
	if viper.GetString("api_keys.ipinfo.api_key") != "" {
		ipInfoData := apis.GetIPInfo(ip, viper.GetString("api_keys.ipinfo.api_key"))
		printIPInfo(ipInfoData)
	}

	if viper.GetString("api_keys.greynoise.api_key") != "" {
		greyNoiseData := apis.GetGreyNoiseData(ip, viper.GetString("api_keys.greynoise.api_key"))
		printGreyNoiseData(greyNoiseData)
	}

	if viper.GetString("api_keys.abuseipdb.api_key") != "" {
		abuseIPDBData := apis.GetAbuseIPDBInfo(ip, viper.GetString("api_keys.abuseipdb.api_key"))
		printAbuseIPDBData(abuseIPDBData)
	}

}

func printIPInfo(ipInfoData *apis.IPInfo) {
	color.Blue("IP information from IPInfo")
	fmt.Printf("IP: %s\nHostname: %s\nOrg: %s\nCountry: %s\n",
		ipInfoData.IP, ipInfoData.Hostname, ipInfoData.Org, ipInfoData.Country)

}

func printGreyNoiseData(greyNoiseData *apis.GreyNoiseInfo) {
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
}

func printAbuseIPDBData(abuseIPDBData *apis.AbuseIPDBResponse) {
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

	}
}

var ipCmd = &cobra.Command{
	Use:   "ip [ipv4]",
	Short: "Analyze an IP address for geolocation, ASN, and threat status",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		input := args[0]
		if err := checkInput(input); err != nil {
			color.Red("Error: %v", err)
			os.Exit(1)
		}
	},
}

func init() {
	ipCmd.Flags().IntVarP(&reportMaxLen, "length", "l", 50, "AbuseIPDB report max length")
	rootCmd.AddCommand(ipCmd)
}

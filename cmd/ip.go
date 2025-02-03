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
	defaultReportEntries = 3
	defaultReportMaxLen  = 100
	greyNoiseAPIKeyMsg   = "GreyNoise API key is missing! Please set the greynoise api_key in config.yaml file."
	ipInfoAPIKeyMsg      = "IPInfo API key is missing! Please set the ipinfo api_key in config.yaml file."
	abuseIPDBAPIKeyMsg   = "AbuseIPDB API key is missing! Please set the abuseipdb api_key in config.yaml file."
)

var reportMaxLen int
var reportEntries int

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
	util.PrintEntry("IP", ipInfoData.IP)
	util.PrintEntry("Hostname", ipInfoData.Hostname)
	util.PrintEntry("Org", ipInfoData.Org)
	util.PrintEntry("Country", ipInfoData.Country)

}

func printGreyNoiseData(greyNoiseData *apis.GreyNoiseInfo) {
	if greyNoiseData != nil {
		color.Blue("\nGreyNoise Threat Intelligence")

		classification := strings.ToUpper(greyNoiseData.Classification)
		switch classification {
		case "MALICIOUS":
			classification = color.RedString(classification)
		case "BENIGN":
			classification = color.GreenString(classification)
		}

		util.PrintEntry("Noise", util.PrintYesNo(greyNoiseData.Noise))
		util.PrintEntry("Riot", util.PrintYesNo(greyNoiseData.Riot))
		util.PrintEntry("Classification", classification)
		util.PrintEntry("Message", greyNoiseData.Message)
		util.PrintEntry("Last seen", greyNoiseData.LastSeen)
		util.PrintEntry("Link", greyNoiseData.Link)
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
		util.PrintEntry("Abuse Confidence Score", abuseIPDBData.Data.AbuseConfidenceScore)
		util.PrintEntry("Total Reports", abuseIPDBData.Data.TotalReports)
		util.PrintEntry("Last Reported At", lastReportDate.Format("Monday, January 2, 2006"))

		// Print the individual reports if available
		if len(abuseIPDBData.Data.Reports) > 0 {
			headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
			columnFmt := color.New(color.FgYellow).SprintfFunc()

			tbl := table.New("Date", "Country", "Comment")
			tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

			for index, report := range abuseIPDBData.Data.Reports {
				if index >= reportEntries {
					break
				}
				humanTime, _ := util.HumanReadableDate(report.ReportedAt)
				tbl.AddRow(humanTime, report.ReporterCountry, util.ShortStr(report.Comment, reportMaxLen))
			}
			fmt.Println()
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
	ipCmd.Flags().IntVarP(&reportMaxLen, "length", "l", defaultReportMaxLen, "AbuseIPDB report max length")
	ipCmd.Flags().IntVarP(&reportEntries, "reports", "r", defaultReportEntries, "AbuseIPDB reports to show")
	rootCmd.AddCommand(ipCmd)
}

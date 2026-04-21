/*
Copyright © 2026 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/alex27riva/soc-cli/internal/apis"
	"github.com/alex27riva/soc-cli/internal/util"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var quotaCmd = &cobra.Command{
	Use:   "quota",
	Short: "Show remaining API usage for VirusTotal, AbuseIPDB, and Urlscan",
	Run:   runQuota,
}

func init() {
	rootCmd.AddCommand(quotaCmd)
}

func runQuota(cmd *cobra.Command, args []string) {
	hasQuota := false

	abuseIPDBAPIKey := viper.GetString("api_keys.abuseipdb.api_key")
	if abuseIPDBAPIKey != "" {
		hasQuota = true
		printAbuseIPDBQuota(abuseIPDBAPIKey)
	} else {
		util.PrintWarning("AbuseIPDB API key not configured")
	}

	urlscanAPIKey := viper.GetString("api_keys.urlscan.api_key")
	if urlscanAPIKey != "" {
		if hasQuota {
			fmt.Println()
		}
		hasQuota = true
		printUrlscanQuota(urlscanAPIKey)
	} else {
		util.PrintWarning("Urlscan API key not configured")
	}

	virustotalAPIKey := viper.GetString("api_keys.virustotal.api_key")
	if virustotalAPIKey != "" {
		if hasQuota {
			fmt.Println()
		}
		hasQuota = true
		printVirusTotalQuota(virustotalAPIKey)
	} else {
		util.PrintWarning("VirusTotal API key not configured")
	}

	if !hasQuota {
		util.PrintError("No API keys configured. Run 'soc-cli config set <service>' to add API keys.")
		os.Exit(1)
	}
}

func printAbuseIPDBQuota(apiKey string) {
	quota := apis.GetAbuseIPDBQuota(apiKey)

	util.PrintHeader("AbuseIPDB API Quota")

	used := quota.DailyLimit - quota.DailyRemaining
	formatQuota("Daily", used, quota.DailyLimit)
}

func printUrlscanQuota(apiKey string) {
	quota, err := apis.GetUrlscanQuota(apiKey)
	if err != nil {
		util.PrintWarning("Error fetching Urlscan quota: %v", err)
		return
	}

	util.PrintHeader("Urlscan API Quota")

	formatQuota("Search (Day)", quota.Limits.Search.Day.Used, quota.Limits.Search.Day.Limit)
	formatQuota("Search (Hour)", quota.Limits.Search.Hour.Used, quota.Limits.Search.Hour.Limit)
	formatQuota("Retrieve (Day)", quota.Limits.Retrieve.Day.Used, quota.Limits.Retrieve.Day.Limit)
	formatQuota("Retrieve (Hour)", quota.Limits.Retrieve.Hour.Used, quota.Limits.Retrieve.Hour.Limit)
	formatQuota("Public (Day)", quota.Limits.Public.Day.Used, quota.Limits.Public.Day.Limit)
	formatQuota("Private (Day)", quota.Limits.Private.Day.Used, quota.Limits.Private.Day.Limit)
	formatQuota("Private (Hour)", quota.Limits.Private.Hour.Used, quota.Limits.Private.Hour.Limit)
}

func printVirusTotalQuota(apiKey string) {
	quota, err := apis.GetVirusTotalQuota(apiKey)
	if err != nil {
		util.PrintWarning("VirusTotal quota not available (may require premium API)")
		return
	}

	util.PrintHeader("VirusTotal API Quota")

	formatQuota("Daily (User)", quota.Daily.User.Used, quota.Daily.User.Allowed)
	formatQuota("Daily (Group)", quota.Daily.Group.Used, quota.Daily.Group.Allowed)

	formatQuota("Hourly (User)", quota.Hourly.User.Used, quota.Hourly.User.Allowed)
	formatQuota("Hourly (Group)", quota.Hourly.Group.Used, quota.Hourly.Group.Allowed)

	formatQuota("Monthly (User)", quota.Monthly.User.Used, quota.Monthly.User.Allowed)
	formatQuota("Monthly (Group)", quota.Monthly.Group.Used, quota.Monthly.Group.Allowed)
}

func formatQuota(name string, used, allowed int) {
	if allowed == 0 {
		util.PrintEntry(name, "N/A")
		return
	}
	remaining := allowed - used
	percentage := float64(used) / float64(allowed) * 100

	var status string
	if percentage >= 90 {
		status = color.RedString("Critical")
	} else if percentage >= 75 {
		status = color.YellowString("Low")
	} else {
		status = color.GreenString("OK")
	}

	util.PrintEntry(name, fmt.Sprintf("%d / %d (%s) - %s", used, allowed, status, formatNumber(remaining)+" remaining"))
}

func formatNumber(n int) string {
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}

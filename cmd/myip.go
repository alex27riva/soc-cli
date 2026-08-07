/*
Copyright © 2025 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/alex27riva/soc-cli/internal/util"

	"github.com/spf13/cobra"
	"resty.dev/v3"
)

type MyIPResult struct {
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

func fetchIP(url string) (net.IP, error) {
	headers := map[string]string{
		"User-Agent": "curl/8.9.1",
	}

	client := resty.New()
	defer client.Close()

	res, err := client.R().
		SetHeaders(headers).
		Get(url)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(strings.TrimSpace(res.String()))
	if ip == nil {
		return nil, fmt.Errorf("invalid IP response from %s", url)
	}
	return ip, nil
}

func getMyIPv4() (net.IP, error) {
	return fetchIP("https://api.ipify.org")
}

func getMyIPv6() (net.IP, error) {
	return fetchIP("https://api6.ipify.org")
}

var myipCmd = &cobra.Command{
	Use:   "myip",
	Short: "Show your public IP address",
	Long:  "Fetches and displays your public IPv4 and/or IPv6 address.",
	Run: func(cmd *cobra.Command, args []string) {
		wantV4, _ := cmd.Flags().GetBool("ipv4")
		wantV6, _ := cmd.Flags().GetBool("ipv6")
		asJSON, _ := cmd.Flags().GetBool("json")

		if !wantV4 && !wantV6 {
			wantV4 = true
			wantV6 = true
		}

		var result MyIPResult

		if wantV4 {
			if ip, err := getMyIPv4(); err != nil {
				if !asJSON {
					util.PrintError("Error fetching IPv4 address: %v", err)
				}
			} else {
				result.IPv4 = ip.String()
			}
		}

		if wantV6 {
			if ip, err := getMyIPv6(); err != nil {
				if !asJSON {
					util.PrintError("Error fetching IPv6 address: %v", err)
				}
			} else {
				result.IPv6 = ip.String()
			}
		}

		if asJSON {
			jsonData, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				util.PrintError("Error marshalling JSON: %v", err)
				return
			}
			fmt.Println(string(jsonData))
			return
		}

		if result.IPv4 != "" {
			util.PrintEntry("IPv4", result.IPv4)
		}
		if result.IPv6 != "" {
			util.PrintEntry("IPv6", result.IPv6)
		}
	},
}

func init() {
	myipCmd.Flags().BoolP("ipv4", "4", false, "Show only your public IPv4 address")
	myipCmd.Flags().BoolP("ipv6", "6", false, "Show only your public IPv6 address")
	myipCmd.Flags().Bool("json", false, "Output result in JSON format")
	miscCmd.AddCommand(myipCmd)
}

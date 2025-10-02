/*
Copyright © 2025 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"fmt"
	"net"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"resty.dev/v3"
)

func getMyIP() net.IP {

	headers := map[string]string{
		"User-Agent": "curl/8.9.1",
	}

	url := "https://ip.me"

	client := resty.New()
	defer client.Close()

	res, err := client.R().
		SetHeaders(headers).
		Get(url)
	if err != nil {
		color.Red("Error fetching API: %v", err)
	}

	ip := strings.TrimSpace(res.String())
	return net.ParseIP(ip)
}

var myipCmd = &cobra.Command{
	Use:   "myip",
	Short: "Get your ip address",
	Long:  "Get your ip address using ip.me API",
	Run: func(cmd *cobra.Command, args []string) {
		ip := getMyIP()
		fmt.Println(ip)
	},
}

func init() {
	miscCmd.AddCommand(myipCmd)
}

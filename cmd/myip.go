/*
Copyright © 2025 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"net"
	"soc-cli/internal/util"
		"github.com/fatih/color"
	"strings"
)

func getMyIP() net.IP {

	headers := map[string]string{
		"User-Agent": "curl/8.9.1",
	}

	url := "https://ip.me"

	body, err := util.GetRaw(url, headers)
	if err != nil {
		color.Red("Error fetching API: %v", err)
	}

	ip := strings.TrimSpace(string(body))
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

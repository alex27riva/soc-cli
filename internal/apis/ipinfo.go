/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package apis

import (
	"fmt"
	"log"
	"net"
	"soc-cli/internal/util"
)

const ipInfoAPIURL = "https://ipinfo.io/%s?token=%s"

type ipInfo struct {
	IP       string `json:"ip"`
	Country  string `json:"country"`
	Hostname string `json:"hostname"`
	Org      string `json:"org"`
}

func GetIPInfo(ip net.IP, apiKey string) *ipInfo {
	apiUrl := fmt.Sprintf(ipInfoAPIURL, ip.String(), apiKey)

	var info ipInfo

	err := util.MakeGETRequest(apiUrl, nil, &info)
	if err != nil {
		log.Fatalf("Error fetching IP info: %v", err)
	}

	return &info
}

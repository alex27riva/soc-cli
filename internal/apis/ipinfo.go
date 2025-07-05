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

	"resty.dev/v3"
)

const ipInfoAPIURL = "https://ipinfo.io/%s?token=%s"

type IPInfo struct {
	IP       string `json:"ip"`
	Country  string `json:"country"`
	Hostname string `json:"hostname"`
	Org      string `json:"org"`
}

func GetIPInfo(ip net.IP, apiKey string) *IPInfo {
	apiUrl := fmt.Sprintf(ipInfoAPIURL, ip.String(), apiKey)

	result := &IPInfo{}

	client := resty.New()
	defer client.Close()

	_, err := client.R().
		SetResult(result).
		Get(apiUrl)
	if err != nil {
		log.Fatalf("Error fetching IP info: %v", err)
	}

	return result
}

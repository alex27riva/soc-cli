/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package apis

import (
	"log"
	"net"

	"resty.dev/v3"
)

const IPInfoBaseURL = "https://ipinfo.io"

type IPInfo struct {
	IP       string `json:"ip"`
	Country  string `json:"country"`
	Hostname string `json:"hostname"`
	Org      string `json:"org"`
}

func GetIPInfo(ip net.IP, apiKey string) *IPInfo {
	client := resty.New()
	defer client.Close()

	client.SetBaseURL(IPInfoBaseURL)

	params := map[string]string{
		"token": apiKey,
	}
	result := &IPInfo{}

	_, err := client.R().
		SetPathParam("ip", ip.String()).
		SetQueryParams(params).
		SetResult(result).
		Get("/{ip}")
	if err != nil {
		log.Fatalf("Error fetching IP info: %v", err)
	}

	return result
}

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

const greyNoiseAPIURL = "https://api.greynoise.io/v3/community/%s"
const greyNoiseBaseURL = "https://api.greynoise.io/v3/community"

type GreyNoiseInfo struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	Riot           bool   `json:"riot"`
	Classification string `json:"classification"`
	Link           string `json:"link"`
	LastSeen       string `json:"last_seen"`
	Message        string `json:"message"`
}

// Get threat intelligence from GreyNoise API
func GetGreyNoiseData(ip net.IP, apiKey string) *GreyNoiseInfo {
	client := resty.New()
	defer client.Close()

	client.SetBaseURL(greyNoiseBaseURL)

	headers := map[string]string{
		"key": apiKey,
	}

	result := &GreyNoiseInfo{}

	_, err := client.R().
		SetHeaders(headers).
		SetPathParam("ip", ip.String()).
		SetResult(result).
		Get("/{ip}")
	if err != nil {
		log.Fatalf("Error fetching AbuseIPDB info: %v", err)
	}

	return result
}

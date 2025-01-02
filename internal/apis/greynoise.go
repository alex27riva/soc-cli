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

const greyNoiseAPIURL = "https://api.greynoise.io/v3/community/%s"

type greyNoiseInfo struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	Riot           bool   `json:"riot"`
	Classification string `json:"classification"`
	Name           string `json:"name"`
	Link           string `json:"link"`
}

// Get threat intelligence from GreyNoise API
func GetGreyNoiseData(ip net.IP, apiKey string) *greyNoiseInfo {
	apiUrl := fmt.Sprintf(greyNoiseAPIURL, ip.String())

	headers := map[string]string{
		"key": apiKey,
	}

	var greyNoiseData greyNoiseInfo

	err := util.MakeGETRequest(apiUrl, headers, &greyNoiseData)
	if err != nil {
		log.Fatalf("Error fetching AbuseIPDB info: %v", err)
	}

	return &greyNoiseData
}

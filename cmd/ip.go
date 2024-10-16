/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"io"
	"log"
	"net/http"
	"os"
)

type ipInfo struct {
	IP           string `json:"ip"`
	Country      string `json:"country"`
	Hostname     string `json:"hostname"`
	Org          string `json:"org"`
	ThreatStatus string `json:"threat"`
}

type greyNoiseInfo struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	Riot           bool   `json:"riot"`
	Classification string `json:"classification"`
	Name           string `json:"name"`
	Link           string `json:"link"`
}

// Get threat intelligence from GreyNoise API
func fetchGreyNoiseData(ip string) (*greyNoiseInfo, error) {
	apiKey := viper.GetString("api_keys.greynoise.api_key")
	if apiKey == "" {
		log.Fatal("GreyNoise API key is missing! Please set the greynoise api_key in config.yaml file")
	}

	apiUrl := fmt.Sprintf("https://api.greynoise.io/v3/community/%s", ip)
	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GreyNoise API request: %v", err)
	}
	req.Header.Set("key", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make GreyNoise API request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read GreyNoise response body: %v", err)
	}

	var greyNoiseData greyNoiseInfo
	err = json.Unmarshal(body, &greyNoiseData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse GreyNoise JSON response: %v", err)
	}

	return &greyNoiseData, nil
}

// analyzeIP fetches and displays IP information using the API
func analyzeIP(ip string) {
	apiKey := viper.GetString("api_keys.ipinfo.api_key")
	if apiKey == "" {
		log.Fatal("API key is missing! Please set the ipinfo_api_key in config.yaml file")
	}

	// Check if is local IP address
	if RFC1918Regex.MatchString(ip) {
		fmt.Printf("The IP provided %s is a RFC1918 bogus IP address.\n", ip)
		os.Exit(0)
	} else if ip == "127.0.0.1" {
		fmt.Printf("The IP provided %s is a loopback IP address.\n", ip)
		os.Exit(0)
	}

	// Construct the request to the IP analysis API (example API URL)
	apiUrl := fmt.Sprintf("https://ipinfo.io/%s?token=%s", ip, apiKey)

	// Make the API request
	resp, err := http.Get(apiUrl)
	if err != nil {
		log.Fatalf("Error making API request: %v", err)
	}
	defer resp.Body.Close()

	// Read and parse the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}

	var info ipInfo
	err = json.Unmarshal(body, &info)
	if err != nil {
		log.Fatalf("Error parsing JSON response: %v", err)
	}

	// Fetch GreyNoise threat intelligence
	greyNoiseData, err := fetchGreyNoiseData(ip)
	if err != nil {
		log.Printf("Error fetching GreyNoise data: %v\n", err)
	}

	// Print the IP information
	fmt.Println(Blue + "IP information from IPInfo" + Reset)
	fmt.Printf("IP: %s\nHostname: %s\nOrg: %s\nCountry: %s\nThreat: %s\n",
		info.IP, info.Hostname, info.Org, info.Country, info.ThreatStatus)

	if greyNoiseData != nil {
		fmt.Println(Blue + "\nGreyNoise Threat Intelligence:" + Reset)

		classification := greyNoiseData.Classification
		if classification == "malicious" {
			classification = fmt.Sprintf("%s%s%s", Red, classification, Reset)
		}

		fmt.Printf("Noise: %v\nRiot: %v\nClassification: %s\nName: %s\nLink: %s\n",
			greyNoiseData.Noise, greyNoiseData.Riot, classification, greyNoiseData.Name, greyNoiseData.Link)
	}
}

var ipCmd = &cobra.Command{
	Use:   "ip [ipv4]",
	Short: "Analyze an IP address for geolocation, ASN, and threat status",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ip := args[0]
		analyzeIP(ip)
	},
}

func init() {
	rootCmd.AddCommand(ipCmd)
}

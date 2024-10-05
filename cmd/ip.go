package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
    "io"
	"github.com/spf13/cobra"
)

// ipInfo stores information retrieved from the IP analysis API
type ipInfo struct {
	IP           string `json:"ip"`
	Country      string `json:"country"`
	Hostname     string `json:"hostname"`
	Org          string `json:"org"`
	ThreatStatus string `json:"threat"`
	// Add more fields as needed based on the API response
}

// analyzeIP fetches and displays IP information using the API
func analyzeIP(ip string) {
	// Fetch API key from environment variable
	apiKey := os.Getenv("IPINFO_API_KEY")
	if apiKey == "" {
		log.Fatal("API key is missing! Please set the IPINFO_API_KEY environment variable.")
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

	// Print the IP information
	fmt.Printf("IP: %s\nHostname: %s\nOrg: %s\nCountry: %s\nThreat: %s\n",
		info.IP, info.Hostname, info.Org, info.Country, info.ThreatStatus)
}

// ipCmd represents the IP analysis command
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

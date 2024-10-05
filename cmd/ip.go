package cmd

import (
    "encoding/json"
    "fmt"
    "net/http"
    "github.com/spf13/cobra"
)

var apiKey = "your_api_key_here"  // Replace with the actual API key

// ipCmd represents the ip command
var ipCmd = &cobra.Command{
    Use:   "ip [ipv4]",
    Short: "Analyze an IP address for geolocation, ASN, and type",
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        ip := args[0]
        analyzeIP(ip)
    },
}

func init() {
    rootCmd.AddCommand(ipCmd)
}

type IPInfo struct {
    IP       string `json:"ip"`
    Country  string `json:"country"`
    City     string `json:"city"`
    Region   string `json:"region"`
    Org      string `json:"org"`
    AS       string `json:"asn"`
    Provider string `json:"hosting_provider"`
    Type     string `json:"type"` // Hosting/VPN/Residential etc.
}

// analyzeIP handles the IP analysis by querying third-party services
func analyzeIP(ip string) {
    url := fmt.Sprintf("https://ipinfo.io/%s/json?token=%s", ip, apiKey)

    resp, err := http.Get(url)
    if err != nil {
        fmt.Println("Error fetching IP data:", err)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        fmt.Println("Error: Non-200 response from API")
        return
    }

    var ipInfo IPInfo
    err = json.NewDecoder(resp.Body).Decode(&ipInfo)
    if err != nil {
        fmt.Println("Error decoding response:", err)
        return
    }

    displayIPInfo(ipInfo)
}

// displayIPInfo prints the fetched IP details
func displayIPInfo(info IPInfo) {
    fmt.Printf("IP: %s\n", info.IP)
    fmt.Printf("Country: %s\n", info.Country)
    fmt.Printf("City: %s\n", info.City)
    fmt.Printf("Region: %s\n", info.Region)
    fmt.Printf("Org: %s\n", info.Org)
    fmt.Printf("ASN: %s\n", info.AS)
    fmt.Printf("Type: %s\n", info.Type)
}


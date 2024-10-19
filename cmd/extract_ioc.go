/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"log"
	"os"
	"soc-cli/internal/util"
)

type iocOutput struct {
	URLs    []string `json:"urls"`
	IPs     []string `json:"ips"`
	Emails  []string `json:"emails"`
	Domains []string `json:"domains"`
	Hashes  []string `json:"hashes"`
}

var extractIocCmd = &cobra.Command{
	Use:   "extract-ioc [file]",
	Short: "Extract Indicators of Compromise (IOCs) from a file",
	Long:  `Extracts IOCs like URLs, IP addresses, email addresses, and file hashes from a specified text file.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]
		asJSON, _ := cmd.Flags().GetBool("json")
		extractIOCs(filePath, asJSON)
	},
}

func init() {
	extractIocCmd.Flags().Bool("json", false, "Output IOCs in JSON format")
	rootCmd.AddCommand(extractIocCmd)
}

func extractIOCs(filePath string, asJSON bool) {

	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Find all IOCs
	uniqueURLs := util.RemoveDuplicates(util.URLRegex.FindAllString(string(data), -1))
	uniqueIPs := util.RemoveDuplicates(util.IPRegex.FindAllString(string(data), -1))
	uniqueEmails := util.RemoveDuplicates(util.EmailRegex.FindAllString(string(data), -1))
	uniqueDomains := util.RemoveDuplicates(util.DomainRegex.FindAllString(string(data), -1))
	uniqueHashes := util.RemoveDuplicates(util.SHA256Regex.FindAllString(string(data), -1))

	if asJSON {
		// Prepare data for JSON output
		iocData := iocOutput{
			URLs:    uniqueURLs,
			IPs:     uniqueIPs,
			Emails:  uniqueEmails,
			Domains: uniqueDomains,
			Hashes:  uniqueHashes,
		}

		// Marshal to JSON and print
		jsonData, err := json.MarshalIndent(iocData, "", "  ")
		if err != nil {
			log.Fatalf("Error marshalling JSON: %v", err)
		}
		fmt.Println(string(jsonData))
	} else {

		if len(uniqueIPs)+len(uniqueURLs)+len(uniqueEmails)+len(uniqueHashes) > 0 {
			color.Blue("Extracted IOCs")
		} else {
			color.Red("No IOCs found")
		}

		// Print IPs
		if len(uniqueIPs) > 0 {
			color.Green("\nIP Addresses:")
			for _, ip := range uniqueIPs {
				fmt.Println(ip)
			}
		}

		// Print URLs
		if len(uniqueURLs) > 0 {
			color.Green("\nURLs:")
			for _, url := range uniqueURLs {
				fmt.Println(url)
			}
		}

		// Print Emails
		if len(uniqueEmails) > 0 {
			color.Green("\nEmail Addresses:")
			for _, email := range uniqueEmails {
				fmt.Println(email)
			}
		}

		// Print Domains
		if len(uniqueDomains) > 0 {
			color.Green("\nDomains:")
			for _, email := range uniqueDomains {
				fmt.Println(email)
			}
		}

		// Print SHA256 Hashes
		if len(uniqueHashes) > 0 {
			color.Green("\nSHA256 Hashes:")
			for _, hash := range uniqueHashes {
				fmt.Println(hash)
			}
		}
	}
}

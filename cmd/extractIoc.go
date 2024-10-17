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
	"log"
	"os"
)

type iocOutput struct {
	URLs   []string `json:"urls"`
	IPs    []string `json:"ips"`
	Emails []string `json:"emails"`
	Hashes []string `json:"hashes"`
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
	uniqueURLs := removeDuplicates(URLRegex.FindAllString(string(data), -1))
	uniqueIPs := removeDuplicates(IPRegex.FindAllString(string(data), -1))
	uniqueEmails := removeDuplicates(EmailRegex.FindAllString(string(data), -1))
	uniqueHashes := removeDuplicates(SHA256Regex.FindAllString(string(data), -1))

	if asJSON {
		// Prepare data for JSON output
		iocData := iocOutput{
			URLs:   uniqueURLs,
			IPs:    uniqueIPs,
			Emails: uniqueEmails,
			Hashes: uniqueHashes,
		}

		// Marshal to JSON and print
		jsonData, err := json.MarshalIndent(iocData, "", "  ")
		if err != nil {
			log.Fatalf("Error marshalling JSON: %v", err)
		}
		fmt.Println(string(jsonData))
	} else {

		if len(uniqueIPs)+len(uniqueURLs)+len(uniqueEmails)+len(uniqueHashes) > 0 {
			fmt.Println(Blue + "Extracted IOCs" + Reset)
		} else {
			fmt.Println(Blue + "No IOCs found" + Reset)
		}

		// Print IPs
		if len(uniqueIPs) > 0 {
			fmt.Println(Green + "\nIP Addresses:" + Reset)
			for _, ip := range uniqueIPs {
				fmt.Println(ip)
			}
		}

		// Print URLs
		if len(uniqueURLs) > 0 {
			fmt.Println(Green + "\nURLs:" + Reset)
			for _, url := range uniqueURLs {
				fmt.Println(url)
			}
		}

		// Print Emails
		if len(uniqueEmails) > 0 {
			fmt.Println(Green + "\nEmail Addresses:" + Reset)
			for _, email := range uniqueEmails {
				fmt.Println(email)
			}
		}

		// Print SHA256 Hashes
		if len(uniqueHashes) > 0 {
			fmt.Println(Green + "\nSHA256 Hashes:" + Reset)
			for _, hash := range uniqueHashes {
				fmt.Println(hash)
			}
		}
	}
}

// Helper function to remove duplicate IOCs
func removeDuplicates(items []string) []string {
	uniqueItems := make(map[string]bool)
	result := []string{}
	for _, item := range items {
		if !uniqueItems[item] {
			uniqueItems[item] = true
			result = append(result, item)
		}
	}
	return result
}

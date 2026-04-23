/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/alex27riva/soc-cli/internal/util"

	"github.com/spf13/cobra"
)

type extractedIOCs struct {
	URLs         []string
	IPs          []string
	Emails       []string
	Domains      []string
	Hashes       []string
	BitcoinAddrs []string
}

func (e extractedIOCs) isEmpty() bool {
	return len(e.URLs) == 0 && len(e.IPs) == 0 && len(e.Emails) == 0 &&
		len(e.Domains) == 0 && len(e.Hashes) == 0 && len(e.BitcoinAddrs) == 0
}

var extractIocCmd = &cobra.Command{
	Use:   "extract-ioc [file]",
	Short: "Extract Indicators of Compromise (IOCs) from a file",
	Long:  `Extracts IOCs like URLs, IP addresses, email addresses, and file hashes from a specified text file.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		noDomains, _ := cmd.Flags().GetBool("no-domains")
		asJSON, _ := cmd.Flags().GetBool("json")

		iocs := extractIOCs(args[0])
		if noDomains {
			iocs.Domains = nil
		}

		if asJSON {
			printIOCsJSON(iocs)
		} else {
			printIOCsText(iocs)
		}
	},
}

func init() {
	extractIocCmd.Flags().Bool("json", false, "Output IOCs in JSON format")
	extractIocCmd.Flags().Bool("no-domains", false, "Do not extract domains")
	rootCmd.AddCommand(extractIocCmd)
}

func extractIOCs(filePath string) extractedIOCs {
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	content := string(data)

	return extractedIOCs{
		IPs:          util.RemoveDuplicates(util.IPRegex.FindAllString(content, -1)),
		URLs:         util.RemoveDuplicates(util.URLRegex.FindAllString(content, -1)),
		Emails:       util.RemoveDuplicates(util.EmailRegex.FindAllString(content, -1)),
		Domains:      util.FilterFileExtensions(util.RemoveDuplicates(util.DomainRegex.FindAllString(content, -1))),
		Hashes:       util.RemoveDuplicates(util.SHA256Regex.FindAllString(content, -1)),
		BitcoinAddrs: util.RemoveDuplicates(util.BitcoinRegex.FindAllString(content, -1)),
	}
}

func printIOCsJSON(iocs extractedIOCs) {
	output := struct {
		URLs         []string `json:"urls,omitempty"`
		IPs          []string `json:"ips,omitempty"`
		Emails       []string `json:"emails,omitempty"`
		Domains      []string `json:"domains,omitempty"`
		Hashes       []string `json:"hashes,omitempty"`
		BitcoinAddrs []string `json:"bitcoin_addresses,omitempty"`
	}{
		URLs:         iocs.URLs,
		IPs:          iocs.IPs,
		Emails:       iocs.Emails,
		Domains:      iocs.Domains,
		Hashes:       iocs.Hashes,
		BitcoinAddrs: iocs.BitcoinAddrs,
	}

	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		log.Fatalf("Error marshalling JSON: %v", err)
	}
	fmt.Println(string(jsonData))
}

func printIOCsText(iocs extractedIOCs) {
	if iocs.isEmpty() {
		util.PrintError("No IOCs found")
		return
	}

	util.PrintHeader("Extracted IOCs")

	printSection("IP Addresses:", iocs.IPs)
	printSection("URLs:", iocs.URLs)
	printSection("Email Addresses:", iocs.Emails)
	printSection("Domains:", iocs.Domains)
	printSection("SHA256 Hashes:", iocs.Hashes)
	printSection("Bitcoin Addresses:", iocs.BitcoinAddrs)
}

func printSection(title string, items []string) {
	if len(items) == 0 {
		return
	}

	util.PrintHeader("\n" + title)
	for _, item := range items {
		fmt.Println(item)
	}
}
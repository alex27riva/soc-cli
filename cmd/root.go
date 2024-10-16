/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "soc",
	Short: "A cli tool for SoC analysts",
	Long: `A CLI tool for security analysts to analyze IP addresses, URLs, and emails.
	It defangs and fangs URLs or email addresses, parses .eml files to list attachments and links,
	 and performs SPF, DKIM, and DMARC validation.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
}

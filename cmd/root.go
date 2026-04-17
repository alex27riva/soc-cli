/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func printSplash() {
	fmt.Printf(`
  ┌─────────────────────────────────┐
  │  (\_/)  S O C - C L I  /══[>   │
  │  (o.O)════════════════/═══[>   │
  │  (> <)  Swiss Army Knife for   │
  │          SOC Analysts  v%s    │
  └─────────────────────────────────┘
`, Version)
}

var rootCmd = &cobra.Command{
	Use:   "soc",
	Short: "A CLI tool for Security Operations Center (SOC) analysts",
	Long:  `soc-cli is a CLI tool for SOC analysts. It supports IP analysis, IOC extraction, file scanning, URL defanging/fanging, encoding/decoding, and more.`,
	Run: func(cmd *cobra.Command, args []string) {
		printSplash()
		_ = cmd.Help()
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
}

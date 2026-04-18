/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"fmt"
	"os"
	"soc-cli/internal/config"

	"github.com/spf13/cobra"
)

var cfgFile string

func printSplash() {
	fmt.Printf(`
  ┌─────────────────────────────────┐
  │  (\_/)  S O C - C L I  /══[>    │
  │  (o.O)════════════════/═══[>    │
  │  (> <)  Swiss Army Knife for    │
  │          SOC Analysts  %s   │
  └─────────────────────────────────┘
`, Version)
}

var rootCmd = &cobra.Command{
	Use:   "soc",
	Short: "A CLI tool for Security Operations Center (SOC) analysts",
	Long:  `soc-cli is a CLI tool for SOC analysts. It supports IP analysis, IOC extraction, file scanning, URL defanging/fanging, encoding/decoding, and more.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return config.InitConfig(cfgFile)
	},
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
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file path (default ~/.config/soc-cli/config.yaml)")
}

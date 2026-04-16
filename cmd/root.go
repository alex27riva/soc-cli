/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"github.com/spf13/cobra"
	"os"
)

var rootCmd = &cobra.Command{
	Use:   "soc",
	Short: "A CLI tool for Security Operations Center (SOC) analysts",
	Long: `soc-cli is a CLI tool for SOC analysts. It supports IP analysis, IOC extraction, file scanning, URL defanging/fanging, encoding/decoding, and more.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
}

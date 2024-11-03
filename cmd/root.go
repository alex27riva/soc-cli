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
	Short: "A cli tool for SoC analysts",
	Long: `soc-cli is a comprehensive command-line application designed for security analysts to streamline threat analysis and incident response.
From IP analysis to IOC extraction, file scanning, and URL defanging, soc-cli offers various commands to support daily tasks in security operations centers.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
}

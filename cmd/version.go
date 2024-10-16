/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var Version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show the version of the program",
	Long:  `Display the current version of this CLI tool.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("soc-cli version %s\n", Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

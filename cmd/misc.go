/*
Copyright © 2025 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"github.com/spf13/cobra"
)

var miscCmd = &cobra.Command{
	Use:   "misc",
	Short: "Miscellaneous network and system utilities",
	Long:  "A collection of miscellaneous utilities including network helpers like myip.",
}

func init() {
	rootCmd.AddCommand(miscCmd)
}

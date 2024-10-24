/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"soc-cli/internal/logic"
)

var fangCmd = &cobra.Command{
	Use:   "fang [input]",
	Short: "Convert defanged URLs or email addresses back to their original form",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		input := args[0]
		result := logic.Fang(input)
		fmt.Println(result)
	},
}

func init() {
	rootCmd.AddCommand(fangCmd)
}

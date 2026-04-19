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
	Args:  cobra.MaximumNArgs(1),
	Run:   executeFang,
}

func executeFang(cmd *cobra.Command, args []string) {
	input := readIOCInput(args, "Enter URL or email to fang: ")
	fmt.Println(logic.Fang(input))
}

func init() {
	rootCmd.AddCommand(fangCmd)
}

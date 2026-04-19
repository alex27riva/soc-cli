/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"fmt"

	"github.com/alex27riva/soc-cli/internal/logic"
	"github.com/alex27riva/soc-cli/internal/util"
	"github.com/spf13/cobra"
)

var fangCmd = &cobra.Command{
	Use:   "fang [input]",
	Short: "Convert defanged URLs or email addresses back to their original form",
	Args:  cobra.MaximumNArgs(1),
	Run:   executeFang,
}

func executeFang(cmd *cobra.Command, args []string) {
	var input string
	if len(args) > 0 {
		input = args[0]
	} else {
		input = util.GetPromptedInput("Enter URL or email to fang: ")
	}
	fmt.Println(logic.Fang(input))
}

func init() {
	rootCmd.AddCommand(fangCmd)
}

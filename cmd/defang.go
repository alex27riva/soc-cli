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
	"soc-cli/internal/util"
)

var defangCmd = &cobra.Command{
	Use:   "defang [input]",
	Short: "Defang a URL or email address to make it safe for sharing",
	Args:  cobra.MaximumNArgs(1),
	Run:   executeDefang,
}

func executeDefang(cmd *cobra.Command, args []string) {
	var input string
	if len(args) > 0 {
		input = args[0]
	} else {
		input = util.GetPromptedInput("Enter URL or email to defang: ")
	}
	defanged := logic.Defang(input)
	fmt.Println(defanged)
}

func init() {
	rootCmd.AddCommand(defangCmd)
}

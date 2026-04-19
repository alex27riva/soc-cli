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

var defangCmd = &cobra.Command{
	Use:   "defang [input]",
	Short: "Defang a URL or email address to make it safe for sharing",
	Args:  cobra.MaximumNArgs(1),
	Run:   executeDefang,
}

func executeDefang(cmd *cobra.Command, args []string) {
	input := readIOCInput(args, "Enter URL or email to defang: ")
	fmt.Println(logic.Defang(input))
}

func init() {
	rootCmd.AddCommand(defangCmd)
}

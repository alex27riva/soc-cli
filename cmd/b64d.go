/*
Copyright © 2025 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"encoding/base64"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/fatih/color"
)

var b64dCmd = &cobra.Command{
	Use:   "b64d <base64-string>",
	Short: "Decode a Base64 string",
	Long:  "Decode a Base64-encoded string and display the original content.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		base64Str := args[0]
		decoded, err := base64.StdEncoding.DecodeString(base64Str)
		if err != nil {
			color.Red("Error decoding Base64 string: %v", err)
		}
		fmt.Println(string(decoded))
	},
}

// Register the b64d subcommand under misc
func init() {
	miscCmd.AddCommand(b64dCmd)
}

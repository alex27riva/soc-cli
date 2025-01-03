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
)

var b64eCmd = &cobra.Command{
	Use:   "b64e <string-to-encode>",
	Short: "Encode a string to Base64",
	Long:  "Encode a string to its Base64 representation.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		input := args[0]
		encoded := base64.StdEncoding.EncodeToString([]byte(input))
		fmt.Println(encoded)
	},
}

// Register the b64e subcommand under misc
func init() {
	miscCmd.AddCommand(b64eCmd)
}
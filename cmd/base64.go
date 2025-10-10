/*
Copyright © 2025 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"encoding/base64"
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var b64eCmd = &cobra.Command{
	Use:   "base64 <string-to-encode>",
	Short: "Encode a string to Base64",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		input := args[0]
		encoded := base64.StdEncoding.EncodeToString([]byte(input))
		fmt.Println(encoded)
	},
	Aliases: []string{"b64"},
}

var b64dCmd = &cobra.Command{
	Use:   "base64 <base64-string>",
	Short: "Decode a Base64 string",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		base64Str := args[0]
		decoded, err := base64.StdEncoding.DecodeString(base64Str)
		if err != nil {
			color.Red("Error decoding Base64 string: %v", err)
		}
		fmt.Println(string(decoded))
	},
	Aliases: []string{"b64"},
}

func init() {
	encodeCmd.AddCommand(b64eCmd)
	decodeCmd.AddCommand(b64dCmd)
}

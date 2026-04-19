/*
Copyright © 2025 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/alex27riva/soc-cli/internal/logic"
	"github.com/alex27riva/soc-cli/internal/util"

	"github.com/spf13/cobra"
)

var b64eCmd = &cobra.Command{
	Use:   "base64 [string-to-encode]",
	Short: "Encode a string to Base64",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var input string
		if len(args) == 1 {
			input = args[0]
		} else {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				util.PrintError("Error reading from stdin: %v", err)
				return
			}
			input = strings.TrimRight(string(data), "\n")
		}
		fmt.Println(logic.Base64Encode(input))
	},
	Aliases: []string{"b64"},
}

var b64dCmd = &cobra.Command{
	Use:   "base64 [base64-string]",
	Short: "Decode a Base64 string",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var base64Str string
		if len(args) == 1 {
			base64Str = args[0]
		} else {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				util.PrintError("Error reading from stdin: %v", err)
				return
			}
			base64Str = strings.TrimRight(string(data), "\n")
		}
		decoded, err := logic.Base64Decode(base64Str)
		if err != nil {
			util.PrintError("Error decoding Base64 string: %v", err)
			return
		}
		fmt.Println(decoded)
	},
	Aliases: []string{"b64"},
}

func init() {
	encodeCmd.AddCommand(b64eCmd)
	decodeCmd.AddCommand(b64dCmd)
}

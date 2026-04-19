/*
Copyright © 2026 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"fmt"
	"io"
	"os"
	"soc-cli/internal/logic"
	"soc-cli/internal/util"
	"strings"

	"github.com/spf13/cobra"
)

var urlEncodeCmd = &cobra.Command{
	Use:   "url [string-to-encode]",
	Short: "URL-encode a string",
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
		fmt.Println(logic.URLEncode(input))
	},
}

var urlDecodeCmd = &cobra.Command{
	Use:   "url [url-encoded-string]",
	Short: "URL-decode a string",
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
		decoded, err := logic.URLDecode(input)
		if err != nil {
			util.PrintError("Error decoding URL-encoded string: %v", err)
			return
		}
		fmt.Println(decoded)
	},
}

func init() {
	encodeCmd.AddCommand(urlEncodeCmd)
	decodeCmd.AddCommand(urlDecodeCmd)
}

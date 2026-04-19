/*
Copyright © 2025 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Show help when invoked with no args; error on unknown subcommand.
func helpOrUnknown(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return cmd.Help()
	}
	return fmt.Errorf("unknown command %q for %q", args[0], cmd.CommandPath())
}

var encodeCmd = &cobra.Command{
	Use:     "encode",
	Short:   "Encode data (Base64, URL, and more)",
	Long:    "Encoding utilities. Currently supports Base64 and URL encoding.",
	Aliases: []string{"enc", "en", "e"},
	RunE:    helpOrUnknown,
}

var decodeCmd = &cobra.Command{
	Use:     "decode",
	Short:   "Decode data (Base64, URL, JWT, and more)",
	Long:    "Decoding utilities. Currently supports Base64, URL decoding, and JWT.",
	Aliases: []string{"dec", "de", "d"},
	RunE:    helpOrUnknown,
}

func init() {
	rootCmd.AddCommand(encodeCmd)
	rootCmd.AddCommand(decodeCmd)
}

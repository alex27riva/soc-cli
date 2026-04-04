/*
Copyright © 2025 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"github.com/spf13/cobra"
)

// Show help if no subcommand is provided
func showHelp(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return cmd.Help()
	}
	return nil
}

var encodeCmd = &cobra.Command{
	Use:     "encode",
	Short:   "Encode data (Base64, and more)",
	Long:    "Encoding utilities. Currently supports Base64.",
	Aliases: []string{"enc", "en", "e"},
	RunE:    showHelp,
}

var decodeCmd = &cobra.Command{
	Use:     "decode",
	Short:   "Decode data (Base64, JWT, and more)",
	Long:    "Decoding utilities. Currently supports Base64 and JWT.",
	Aliases: []string{"dec", "de", "d"},
	RunE:    showHelp,
}

func init() {
	rootCmd.AddCommand(encodeCmd)
	rootCmd.AddCommand(decodeCmd)
}

/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
    "fmt"
    "strings"
    "github.com/spf13/cobra"
)

// fang reverses the defanged URLs or email addresses
func fang(input string) string {
    // Replace 'hxxp' or 'hxxps' with 'http' or 'https'
    fanged := strings.Replace(input, "hxxp", "http", -1)
    fanged = strings.Replace(fanged, "hxxps", "https", -1)

    // Replace '[.]' back to '.'
    fanged = strings.Replace(fanged, "[.]", ".", -1)

    // Replace '[at]' or similar with '@' for email addresses
    fanged = strings.Replace(fanged, "[at]", "@", -1)
    fanged = strings.Replace(fanged, "(at)", "@", -1)
    fanged = strings.Replace(fanged, "[@]", "@", -1)

    return fanged
}

// fangCmd represents the "fang" command
var fangCmd = &cobra.Command{
    Use:   "fang [input]",
    Short: "Convert defanged URLs or email addresses back to their original form",
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        input := args[0]
        result := fang(input)
        fmt.Println(result)
    },
}

func init() {
    rootCmd.AddCommand(fangCmd)
}

/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
    "fmt"
    "regexp"
    "strings"
    "github.com/spf13/cobra"
)

var defangCmd = &cobra.Command{
    Use:   "defang [input]",
    Short: "Defang a URL or email address to make it safe for sharing",
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        input := args[0]
        defanged := defangInput(input)
        fmt.Println(defanged)
    },
}

func init() {
    rootCmd.AddCommand(defangCmd)
}

// defangInput checks if the input is a URL or email and defangs it accordingly
func defangInput(input string) string {
    // Check if the input is an email address using a regex
    emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
    if emailRegex.MatchString(input) {
        return defangEmail(input)
    }

    // Otherwise, assume it is a URL and defang it
    return defangURL(input)
}

// defangEmail converts an email address to its defanged format
func defangEmail(email string) string {
    // Replace "@" with "[at]" and "." with "[.]"
    defanged := strings.Replace(email, "@", "[at]", 1)
    defanged = strings.Replace(defanged, ".", "[.]", -1)

    return defanged
}

// defangURL converts a URL to its defanged format
func defangURL(url string) string {
    // Replace protocol
    defanged := strings.Replace(url, "http://", "hxxp://", 1)
    defanged = strings.Replace(defanged, "https://", "hxxps://", 1)

    // Replace dots
    defanged = strings.Replace(defanged, ".", "[.]", -1)

    return defanged
}

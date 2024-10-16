/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"bufio"
	"fmt"
	"github.com/spf13/cobra"
	"log"
	"os"
	"regexp"
	"strings"
)

var defangCmd = &cobra.Command{
	Use:   "defang [input]",
	Short: "Defang a URL or email address to make it safe for sharing",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var input string

		if len(args) > 0 {
			input = args[0]
		} else {
			fmt.Print("Enter URL or email to defang: ")
			reader := bufio.NewReader(os.Stdin)
			in, err := reader.ReadString('\n')
			if err != nil {
				log.Fatalf("Error reading input: %v", err)
			}
			input = strings.TrimSpace(in)
		}

		defanged := defang(input)
		fmt.Println(defanged)
	},
}

func init() {
	rootCmd.AddCommand(defangCmd)
}

func defang(input string) string {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if emailRegex.MatchString(input) {
		return defangEmail(input)
	}

	return defangURL(input)
}

func defangEmail(email string) string {
	defanged := strings.Replace(email, "@", "[at]", 1)
	defanged = strings.Replace(defanged, ".", "[.]", -1)

	return defanged
}

func defangURL(url string) string {
	defanged := strings.Replace(url, "http://", "hxxp://", 1)
	defanged = strings.Replace(defanged, "https://", "hxxps://", 1)
	defanged = strings.Replace(defanged, ".", "[.]", -1)

	return defanged
}

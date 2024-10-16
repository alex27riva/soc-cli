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
	"runtime"
	"strings"
)

var defangCmd = &cobra.Command{
	Use:   "defang [input]",
	Short: "Defang a URL or email address to make it safe for sharing",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var input string

		if len(args) > 0 {
			fmt.Println(len(args))
			input = args[0]
		} else {
			if !isInputFromPipe() {
				fmt.Print("Enter URL or email to defang: ")
			}

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

// isInputFromPipe checks if the standard input is coming from a pipe
func isInputFromPipe() bool {
	// Check if stdin is a terminal
	return !isTerminal(os.Stdin.Fd())
}

// isTerminal checks if the given file descriptor is a terminal
func isTerminal(fd uintptr) bool {
	return runtime.GOOS != "windows" && isatty(fd)
}

// isatty checks if the file descriptor is a terminal (Unix-like systems)
func isatty(fd uintptr) bool {
	// Use the syscall package to check if the file descriptor is a terminal
	// This is a simplified version; you may need to import "golang.org/x/sys/unix" for a complete implementation
	return false // Placeholder; implement actual check if needed
}

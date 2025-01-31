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
	"os"
	"runtime"
	"soc-cli/internal/logic"
	"github.com/fatih/color"
	"strings"
)

var defangCmd = &cobra.Command{
	Use:   "defang [input]",
	Short: "Defang a URL or email address to make it safe for sharing",
	Args:  cobra.MaximumNArgs(1),
	Run:   executeDefang,
}

func executeDefang(cmd *cobra.Command, args []string) {
	input := getInput(args)
	defanged := logic.Defang(input)
	fmt.Println(defanged)
}

func getInput(args []string) string {
	if len(args) > 0 {
		return args[0]
	} else {
		if !isInputFromPipe() {
			fmt.Print("Enter URL or email to defang: ")
		}

		reader := bufio.NewReader(os.Stdin)
		in, err := reader.ReadString('\n')
		if err != nil {
			color.Red("Error reading input: %v", err)
		}
		return strings.TrimSpace(in)
	}
}

func init() {
	rootCmd.AddCommand(defangCmd)
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

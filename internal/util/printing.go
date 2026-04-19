/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package util

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"golang.org/x/term"
)

func PrintHeader(format string, a ...interface{}) {
	color.Blue(format, a...)
}

func PrintError(format string, a ...interface{}) {
	color.Red(format, a...)
}

func PrintSuccess(format string, a ...interface{}) {
	color.Green(format, a...)
}

func PrintWarning(format string, a ...interface{}) {
	color.Yellow(format, a...)
}

func PrintEntry(entryName string, entryValue interface{}) {
	if entryValue != nil {
		switch v := entryValue.(type) {
		case string:
			if v != "" {
				fmt.Printf("%s: %s\n", color.CyanString(entryName), v)
			}
		case bool:
			fmt.Printf("%s: %t\n", color.CyanString(entryName), v)
		case int:
			fmt.Printf("%s: %d\n", color.CyanString(entryName), v)
		default:
			fmt.Printf("%s: %v\n", color.CyanString(entryName), v)
		}
	}
}

func PrintYesNo(val bool) string {
	if val {
		return color.GreenString("YES")
	}
	return color.RedString("NO")
}

// getPromptedInput prompts the user for input if the standard input is not a pipe
func GetPromptedInput(prompt string) string {
	if !isInputFromPipe() {
		fmt.Print(prompt)
	}

	reader := bufio.NewReader(os.Stdin)
	in, err := reader.ReadString('\n')
	if err != nil {
		color.Red("Error reading input: %v", err)
	}
	return strings.TrimSpace(in)
}

// isInputFromPipe checks if the standard input is coming from a pipe
func isInputFromPipe() bool {
	return !term.IsTerminal(int(os.Stdin.Fd()))
}

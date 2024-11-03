/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"bufio"
	"fmt"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"log"
	"os"
	"unicode"
)

var minLength int
var asciiOnly bool

var stringsCmd = &cobra.Command{
	Use:   "strings [file]",
	Short: "Extract printable strings from a file",
	Long:  `The strings command scans a binary or any file for printable sequences of characters. Useful for malware analysis or file inspection.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]
		extractStrings(filePath)
	},
}

func init() {
	stringsCmd.Flags().IntVarP(&minLength, "min-length", "m", 5, "Minimum length of strings to extract")
	stringsCmd.Flags().BoolVarP(&asciiOnly, "ascii", "a", false, "Extract only ASCII printable characters")
	rootCmd.AddCommand(stringsCmd)
}

// extractStrings extracts printable strings from a file
func extractStrings(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Could not open file: %v", err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	var result []rune

	color.Blue("Extracting strings from file: %s (Minimum length: %d)\n", filePath, minLength)

	for {
		char, _, err := reader.ReadRune()
		if err != nil {
			break
		}

		// Check if the character is printable
		if isPrintable(char) {
			result = append(result, char)
		} else {
			// If we encounter a non-printable character and result has enough characters, print the string
			if len(result) >= minLength {
				fmt.Println(string(result))
			}
			result = result[:0] // Reset result
		}
	}

	// Print the remaining string if it's long enough
	if len(result) >= minLength {
		fmt.Println(string(result))
	}
}

func isPrintable(char rune) bool {
	if asciiOnly {
		return char >= 32 && char <= 126 // ASCII printable characters
	}
	return unicode.IsPrint(char) // General Unicode printable characters
}

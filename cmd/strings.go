/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"unicode"

	"github.com/spf13/cobra"
)

var minLength int
var unicodeMode bool

var stringsCmd = &cobra.Command{
	Use:   "strings [file]",
	Short: "Extract printable strings from a file",
	Long:  `The strings command scans a binary or any file for printable sequences of characters. Useful for malware analysis or file inspection.`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			extractStrings(os.Stdin)
			return
		}
		file, err := os.Open(args[0])
		if err != nil {
			log.Fatalf("Could not open file: %v", err)
		}
		defer file.Close()
		extractStrings(file)
	},
}

func init() {
	stringsCmd.Flags().IntVarP(&minLength, "min-length", "n", 4, "Minimum length of strings to extract")
	stringsCmd.Flags().BoolVarP(&unicodeMode, "unicode", "u", false, "Include non-ASCII Unicode printable characters")
	rootCmd.AddCommand(stringsCmd)
}

func extractStrings(f *os.File) {
	if unicodeMode {
		extractUnicode(f)
	} else {
		extractASCII(f)
	}
}

func extractASCII(f *os.File) {
	reader := bufio.NewReader(f)
	var current []byte

	flush := func() {
		if len(current) >= minLength {
			fmt.Println(string(current))
		}
		current = current[:0]
	}

	for {
		b, err := reader.ReadByte()
		if err != nil {
			break
		}
		if (b >= 0x20 && b <= 0x7e) || b == '\f' {
			current = append(current, b)
		} else {
			flush()
		}
	}
	flush()
}

func extractUnicode(f *os.File) {
	reader := bufio.NewReader(f)
	var current []rune

	flush := func() {
		if len(current) >= minLength {
			fmt.Println(string(current))
		}
		current = current[:0]
	}

	for {
		r, _, err := reader.ReadRune()
		if err != nil {
			break
		}
		if unicode.IsPrint(r) {
			current = append(current, r)
		} else {
			flush()
		}
	}
	flush()
}

/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"bufio"
	"fmt"
	"os"

	"github.com/alex27riva/soc-cli/internal/logic"
	"github.com/alex27riva/soc-cli/internal/util"
	"github.com/spf13/cobra"
)

var (
	defangFile string
)

var defangCmd = &cobra.Command{
	Use:   "defang [input]",
	Short: "Defang a URL or email address to make it safe for sharing",
	Args:  cobra.MaximumNArgs(1),
	Run:   executeDefang,
}

func executeDefang(cmd *cobra.Command, args []string) {
	if defangFile != "" {
		file, err := os.Open(defangFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if line != "" {
				fmt.Println(logic.Defang(line))
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}
		return
	}

	var input string
	if len(args) > 0 {
		input = args[0]
	} else {
		input = util.GetPromptedInput("Enter URL or email to defang: ")
	}
	fmt.Println(logic.Defang(input))
}

func init() {
	defangCmd.Flags().StringVarP(&defangFile, "file", "f", "", "Read a list of IOCs from a file (one per line)")
	rootCmd.AddCommand(defangCmd)
}

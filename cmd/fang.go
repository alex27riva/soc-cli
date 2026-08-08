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
	fangFile string
)

var fangCmd = &cobra.Command{
	Use:   "fang [input]",
	Short: "Convert defanged URLs or email addresses back to their original form",
	Args:  cobra.MaximumNArgs(1),
	Run:   executeFang,
}

func executeFang(cmd *cobra.Command, args []string) {
	if fangFile != "" {
		file, err := os.Open(fangFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if line != "" {
				fmt.Println(logic.Fang(line))
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
		input = util.GetPromptedInput("Enter URL or email to fang: ")
	}
	fmt.Println(logic.Fang(input))
}

func init() {
	fangCmd.Flags().StringVarP(&fangFile, "file", "f", "", "Read a list of IOCs from a file (one per line)")
	rootCmd.AddCommand(fangCmd)
}

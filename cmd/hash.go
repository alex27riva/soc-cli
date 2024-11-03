/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"os"
	"soc-cli/internal/logic"
)

func openFile(filePath string) (*os.File, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	return file, nil
}

var hashCmd = &cobra.Command{
	Use:   "hash [file]",
	Args:  cobra.ExactArgs(1),
	Short: "Calculate file hashes",
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]

		file, err := openFile(filePath)
		if err != nil {
			fmt.Printf("Error opening file %v", err)
		}

		defer file.Close()

		fmt.Println(color.GreenString("MD5:"), logic.ComputeMd5(file))
		// Reset the file pointer to the beginning
		file.Seek(0, 0)
		fmt.Println(color.GreenString("SHA1:"), logic.ComputeSha1(file))
		file.Seek(0, 0)
		fmt.Println(color.GreenString("SHA-256:"), logic.ComputeSha256(file))
	},
}

func init() {
	rootCmd.AddCommand(hashCmd)
}

/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"log"
	"os"
	"soc-cli/internal/logic"
)

type hashOutput struct {
	MD5    string `json:"MD5"`
	SHA1   string `json:"SHA1"`
	SHA256 string `json:"SHA256"`
}

func openFile(filePath string) (*os.File, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	return file, nil
}

func showHashes(filePath string, asJson bool) {
	file, err := openFile(filePath)
	if err != nil {
		fmt.Printf("Error opening file %v", err)
	}

	defer file.Close()

	md5Digest := logic.ComputeMd5(file)
	// Reset the file pointer to the beginning
	file.Seek(0, 0)
	sha1Digest := logic.ComputeSha1(file)
	file.Seek(0, 0)
	sha256 := logic.ComputeSha256(file)

	if asJson {

		hashData := hashOutput{
			MD5:    md5Digest,
			SHA1:   sha1Digest,
			SHA256: sha1Digest}

		// Marshal to JSON and print
		jsonData, err := json.MarshalIndent(hashData, "", "  ")
		if err != nil {
			log.Fatalf("Error marshalling JSON: %v", err)
		}
		fmt.Println(string(jsonData))

	} else {

		fmt.Println(color.GreenString("MD5:"), md5Digest)
		fmt.Println(color.GreenString("SHA1:"), sha1Digest)
		fmt.Println(color.GreenString("SHA-256:"), sha256)

	}

}

var hashCmd = &cobra.Command{
	Use:   "hash [file]",
	Args:  cobra.ExactArgs(1),
	Short: "Calculate file hashes",
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]
		asJSON, _ := cmd.Flags().GetBool("json")
		showHashes(filePath, asJSON)
	},
}

func init() {
	hashCmd.Flags().Bool("json", false, "Output hashes in JSON format")
	rootCmd.AddCommand(hashCmd)
}

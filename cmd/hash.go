/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"soc-cli/internal/logic"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
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

	md5Digest := logic.ComputeFileMd5(file)
	sha1Digest := logic.ComputeFileSha1(file)
	sha256Digest := logic.ComputeFileSha256(file)

	if asJson {

		hashData := hashOutput{
			MD5:    md5Digest,
			SHA1:   sha1Digest,
			SHA256: sha256Digest}

		// Marshal to JSON and print
		jsonData, err := json.MarshalIndent(hashData, "", "  ")
		if err != nil {
			log.Fatalf("Error marshalling JSON: %v", err)
		}
		fmt.Println(string(jsonData))

	} else {

		fmt.Println(color.GreenString("MD5:"), md5Digest)
		fmt.Println(color.GreenString("SHA1:"), sha1Digest)
		fmt.Println(color.GreenString("SHA256:"), sha256Digest)

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

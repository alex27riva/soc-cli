/*
Copyright © 2024 Alessandro Riva
*/
package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/spf13/cobra"
	"io"
	"os"
)

const (
	Reset = "\033[0m"
	Green = "\033[32m"
	Red   = "\033[31m"
)

func computeHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf( Red + "failed to open file: %w" + Reset, err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf(Red + "failed to hash file: %w" + Reset, err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// hashCmd represents the hash command
var hashCmd = &cobra.Command{
	Use:   "hash [file]",
	Args:  cobra.ExactArgs(1),
	Short: "Calculate the SHA-256 hash of a file",
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]

		// Calculate SHA-256 hash
		fileHash, err := computeHash(filePath)
		if err != nil {
			fmt.Printf("Error calculating hash: %v", err)
		} else {
			fmt.Println(Green + "SHA-256:" + Reset, fileHash)
		}

		
	},
}

func init() {
	rootCmd.AddCommand(hashCmd)
}

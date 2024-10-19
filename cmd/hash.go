/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"io"
	"log"
	"os"
)

func openFile(filePath string) (*os.File, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	return file, nil
}

func calculateMd5(file *os.File) string {
	hmd5 := md5.New()
	if _, err := io.Copy(hmd5, file); err != nil {
		log.Fatal("failed to calculate MD5 of file: %w", err)
	}
	hashmd5 := hmd5.Sum(nil)
	hexmd5 := fmt.Sprintf("%x", hashmd5)
	return hexmd5
}

func calculateSha1(file *os.File) string {
	h1 := sha1.New()
	if _, err := io.Copy(h1, file); err != nil {
		log.Fatal("failed to calculate SHA1 of file: %w", err)
	}
	hashsha1 := h1.Sum(nil)
	hex1 := fmt.Sprintf("%x", hashsha1)
	return hex1
}

func calculateSha256(file *os.File) string {
	h256 := sha256.New()
	if _, err := io.Copy(h256, file); err != nil {
		log.Fatal("failed to calculate SHA256 of file: %w", err)
	}
	hash256 := h256.Sum(nil)
	hex256 := fmt.Sprintf("%x", hash256)
	return hex256
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

		fmt.Println(color.GreenString("MD5:"), calculateMd5(file))
		// Reset the file pointer to the beginning
		file.Seek(0, 0)
		fmt.Println(color.GreenString("SHA1:"), calculateSha1(file))
		file.Seek(0, 0)
		fmt.Println(color.GreenString("SHA-256:"), calculateSha256(file))
	},
}

func init() {
	rootCmd.AddCommand(hashCmd)
}

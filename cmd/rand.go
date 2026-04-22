/*
Copyright © 2026 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
)

func runRand(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %v", err)
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

func runRandHex(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %v", err)
	}
	return hex.EncodeToString(bytes), nil
}

var randCmd = &cobra.Command{
	Use:   "rand [length]",
	Args:  cobra.MaximumNArgs(1),
	Short: "Generate cryptographically secure random strings",
	Long:  "Generate cryptographically secure random strings in different formats (base64, hex)",
	RunE: func(cmd *cobra.Command, args []string) error {
		length := 32
		if len(args) > 0 {
			var err error
		length, err = strconv.Atoi(args[0])
			if err != nil || length <= 0 {
				return fmt.Errorf("invalid length: %s", args[0])
			}
		}
		output, err := runRand(length)
		if err != nil {
			return err
		}
		fmt.Println(output)
		return nil
	},
}

var randBase64Cmd = &cobra.Command{
	Use:   "base64 [length]",
	Aliases: []string{"b64"},
	Args:  cobra.MaximumNArgs(1),
	Short: "Generate base64 encoded random string",
	Example: `  soc-cli rand base64 32
  soc-cli rand b64 16`,
	RunE: func(cmd *cobra.Command, args []string) error {
		length := 32
		if len(args) > 0 {
			var err error
		length, err = strconv.Atoi(args[0])
			if err != nil || length <= 0 {
				return fmt.Errorf("invalid length: %s", args[0])
			}
		}
		output, err := runRand(length)
		if err != nil {
			return err
		}
		fmt.Println(output)
		return nil
	},
}

var randHexCmd = &cobra.Command{
	Use:   "hex [length]",
	Args:  cobra.MaximumNArgs(1),
	Short: "Generate hexadecimal encoded random string",
	Example: `  soc-cli rand hex 32`,
	RunE: func(cmd *cobra.Command, args []string) error {
		length := 32
		if len(args) > 0 {
			var err error
		length, err = strconv.Atoi(args[0])
			if err != nil || length <= 0 {
				return fmt.Errorf("invalid length: %s", args[0])
			}
		}
		output, err := runRandHex(length)
		if err != nil {
			return err
		}
		fmt.Println(output)
		return nil
	},
}

func init() {
	randCmd.AddCommand(randBase64Cmd)
	randCmd.AddCommand(randHexCmd)
	rootCmd.AddCommand(randCmd)
}
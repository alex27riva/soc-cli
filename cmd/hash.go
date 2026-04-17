/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"soc-cli/internal/logic"
	"soc-cli/internal/util"

	"github.com/spf13/cobra"
)

func showHashes(filePath string, asJSON bool) {
	results, err := logic.HashFile(filePath)
	if err != nil {
		util.PrintError("%v", err)
		return
	}

	if asJSON {
		m := make(map[string]string, len(results))
		for _, r := range results {
			m[r.Name] = r.Hex
		}
		jsonData, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			util.PrintError("Error marshalling JSON: %v", err)
			return
		}
		fmt.Println(string(jsonData))
		return
	}

	for _, r := range results {
		util.PrintEntry(r.Name, r.Hex)
	}
}

var hashCmd = &cobra.Command{
	Use:   "hash [file]",
	Args:  cobra.ExactArgs(1),
	Short: "Calculate file hashes",
	Run: func(cmd *cobra.Command, args []string) {
		asJSON, _ := cmd.Flags().GetBool("json")
		showHashes(args[0], asJSON)
	},
}

func init() {
	hashCmd.Flags().Bool("json", false, "Output hashes in JSON format")
	rootCmd.AddCommand(hashCmd)
}

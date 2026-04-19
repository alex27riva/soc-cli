/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/alex27riva/soc-cli/internal/logic"
	"github.com/alex27riva/soc-cli/internal/util"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func showHashes(filePath string, asJSON, showDeprecated bool) {
	algos := logic.HashAlgorithms
	if !showDeprecated {
		filtered := make([]logic.HashAlgorithm, 0, len(algos))
		for _, a := range algos {
			if !a.Deprecated {
				filtered = append(filtered, a)
			}
		}
		algos = filtered
	}

	results, err := logic.HashFileWith(filePath, algos)
	if err != nil {
		util.PrintError("%v", err)
		return
	}

	if asJSON {
		var b strings.Builder
		b.WriteString("{\n")
		for i, r := range results {
			key, _ := json.Marshal(r.Name)
			val, _ := json.Marshal(r.Hex)
			fmt.Fprintf(&b, "  %s: %s", key, val)
			if i < len(results)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString("}")
		fmt.Println(b.String())
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
		// Flag overrides config; otherwise fall back to hash.show_deprecated.
		showDeprecated := viper.GetBool("hash.show_deprecated")
		if cmd.Flags().Changed("show-deprecated") {
			showDeprecated, _ = cmd.Flags().GetBool("show-deprecated")
		}
		showHashes(args[0], asJSON, showDeprecated)
	},
}

func init() {
	hashCmd.Flags().Bool("json", false, "Output hashes in JSON format")
	hashCmd.Flags().BoolP("show-deprecated", "d", false, "Also compute deprecated hashes (MD5, SHA1)")
	rootCmd.AddCommand(hashCmd)
}

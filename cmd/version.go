/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"log"
)

var Version = "v01.0"

type verOutput struct {
	Version string `json:"version"`
}

func displayVersion(asJSON bool) {
	if asJSON {
		jsonData, err := json.MarshalIndent(verOutput{Version: Version}, "", " ")
		if err != nil {
			log.Fatalf("Error marshalling JSON: %v", err)
		}
		fmt.Println(string(jsonData))

	} else {
		fmt.Printf("soc-cli version: %s\n", Version)
	}

}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show the version of the program",
	Long:  `Display the current version of this CLI tool.`,
	Run: func(cmd *cobra.Command, args []string) {
		asJSON, _ := cmd.Flags().GetBool("json")
		displayVersion(asJSON)
	},
}

func init() {
	versionCmd.Flags().Bool("json", false, "Output version in JSON format")
	rootCmd.AddCommand(versionCmd)
}

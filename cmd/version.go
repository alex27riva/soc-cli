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

	"github.com/alex27riva/soc-cli/internal/util"
	"github.com/alex27riva/soc-cli/internal/version"

	"github.com/spf13/cobra"
)

type VersionInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

func displayVersion(asJSON bool) {
	if asJSON {
		versionInfo := VersionInfo{
			Version: version.Version,
			Commit:  version.GitCommit,
			Date:    version.BuildDate,
		}
		jsonData, err := json.MarshalIndent(versionInfo, "", "  ")
		if err != nil {
			log.Fatalf("Error marshalling JSON: %v", err)
		}
		fmt.Println(string(jsonData))

	} else {
		util.PrintEntry("Version", version.Version)
		util.PrintEntry("Commit", version.GitCommit)
		util.PrintEntry("Date", version.BuildDate)
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

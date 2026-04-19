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
	"runtime/debug"
	"time"

	"github.com/alex27riva/soc-cli/internal/util"

	"github.com/spf13/cobra"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

type VersionInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

func displayVersion(asJSON bool) {
	if asJSON {
		versionInfo := VersionInfo{
			Version: Version,
			Commit:  Commit,
			Date:    Date,
		}
		jsonData, err := json.MarshalIndent(versionInfo, "", "  ")
		if err != nil {
			log.Fatalf("Error marshalling JSON: %v", err)
		}
		fmt.Println(string(jsonData))

	} else {
		util.PrintEntry("Version", Version)
		util.PrintEntry("Commit", Commit)
		util.PrintEntry("Date", Date)
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
	if Version == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok {
			if info.Main.Version != "" {
				Version = info.Main.Version
			}
			for _, s := range info.Settings {
				switch s.Key {
				case "vcs.revision":
					Commit = s.Value
				case "vcs.time":
					if t, err := time.Parse(time.RFC3339, s.Value); err == nil {
						Date = t.UTC().Format("20060102")
					} else {
						Date = s.Value
					}
				}
			}
		}
	}
	versionCmd.Flags().Bool("json", false, "Output version in JSON format")
	rootCmd.AddCommand(versionCmd)
}

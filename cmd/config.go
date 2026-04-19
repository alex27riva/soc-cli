/*
Copyright © 2025 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/alex27riva/soc-cli/internal/util"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

var knownServices = []string{"urlscan", "ipinfo", "greynoise", "abuseipdb", "virustotal"}

func viperKey(service string) string {
	return fmt.Sprintf("api_keys.%s.api_key", service)
}

func maskKey(key string) string {
	if key == "" {
		return color.YellowString("(not set)")
	}
	if len(key) <= 8 {
		return strings.Repeat("*", len(key))
	}
	return key[:4] + strings.Repeat("*", len(key)-4)
}

func isKnownService(service string) bool {
	for _, s := range knownServices {
		if s == service {
			return true
		}
	}
	return false
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage API keys in the config file",
	RunE:  helpOrUnknown,
}

var configListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configured API keys",
	Run: func(cmd *cobra.Command, args []string) {
		showFull, _ := cmd.Flags().GetBool("show")
		util.PrintHeader("API Keys:")
		for _, service := range knownServices {
			key := viper.GetString(viperKey(service))
			var display string
			if showFull {
				if key == "" {
					display = color.YellowString("(not set)")
				} else {
					display = key
				}
			} else {
				display = maskKey(key)
			}
			util.PrintEntry(service, display)
		}
	},
}

var configSetCmd = &cobra.Command{
	Use:   "set <service>",
	Short: "Set an API key for a service (prompted securely, not echoed)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		service := strings.ToLower(args[0])

		if !isKnownService(service) {
			util.PrintError("Unknown service %q. Known services: %s", service, strings.Join(knownServices, ", "))
			os.Exit(1)
		}

		fmt.Printf("Enter API key for %q: ", service)
		keyBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			util.PrintError("Failed to read API key: %v", err)
			os.Exit(1)
		}
		apiKey := strings.TrimSpace(string(keyBytes))
		if apiKey == "" {
			util.PrintError("API key cannot be empty.")
			os.Exit(1)
		}

		viper.Set(viperKey(service), apiKey)
		if err := viper.WriteConfig(); err != nil {
			util.PrintError("Error writing config: %v", err)
			os.Exit(1)
		}
		util.PrintSuccess("API key for %q saved.", service)
	},
}

var configDeleteCmd = &cobra.Command{
	Use:   "delete <service>",
	Short: "Clear the API key for a service",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		service := strings.ToLower(args[0])

		if !isKnownService(service) {
			util.PrintError("Unknown service %q. Known services: %s", service, strings.Join(knownServices, ", "))
			os.Exit(1)
		}

		viper.Set(viperKey(service), "")
		if err := viper.WriteConfig(); err != nil {
			util.PrintError("Error writing config: %v", err)
			os.Exit(1)
		}
		util.PrintSuccess("API key for %q cleared.", service)
	},
}

func init() {
	configListCmd.Flags().Bool("show", false, "Show full API key values")
	configCmd.AddCommand(configListCmd)
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configDeleteCmd)
	rootCmd.AddCommand(configCmd)
}

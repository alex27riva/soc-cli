/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"log/slog"

	"github.com/fatih/color"

	"github.com/spf13/viper"
)

func InitConfig() error {

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not find home directory: %v", err)
	}

	configPath := filepath.Join(home, ".config", "soc-cli")

	// Create the directory if it doesn't exist
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := os.MkdirAll(configPath, os.ModePerm); err != nil {
			return fmt.Errorf("could not create config directory: %v", err)
		}
	}

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(configPath)

	viper.SetDefault("api_keys.urlscan.api_key", "")
	viper.SetDefault("api_keys.ipinfo.api_key", "")
	viper.SetDefault("api_keys.greynoise.api_key", "")
	viper.SetDefault("api_keys.abuseipdb.api_key", "")
	viper.SetDefault("api_keys.virustotal.api_key", "")

	if err := viper.SafeWriteConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileAlreadyExistsError); ok {
			slog.Debug("Config file already exists, reading existing config")
			if err := viper.ReadInConfig(); err != nil {
				return fmt.Errorf("error reading config file: %v", err)
			}
		} else {
			return fmt.Errorf("error writing config file: %v", err)
		}
	} else {
		color.Green("First execution, config file created")
		os.Exit(0)
	}

	return nil
}

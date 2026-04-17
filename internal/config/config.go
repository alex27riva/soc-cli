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

func setDefaults() {
	viper.SetDefault("api_keys.urlscan.api_key", "")
	viper.SetDefault("api_keys.ipinfo.api_key", "")
	viper.SetDefault("api_keys.greynoise.api_key", "")
	viper.SetDefault("api_keys.abuseipdb.api_key", "")
	viper.SetDefault("api_keys.virustotal.api_key", "")

	viper.SetDefault("hash.show_deprecated", false)
}

// InitConfig loads configuration. If configFile is non-empty it is read
// as-is (erroring if missing). Otherwise the default location
// ~/.config/soc-cli/config.yaml is used, and created on first run.
func InitConfig(configFile string) error {
	setDefaults()

	if configFile != "" {
		viper.SetConfigFile(configFile)
		if err := viper.ReadInConfig(); err != nil {
			return fmt.Errorf("error reading config file %s: %v", configFile, err)
		}
		return nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not find home directory: %v", err)
	}

	configPath := filepath.Join(home, ".config", "soc-cli")

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := os.MkdirAll(configPath, os.ModePerm); err != nil {
			return fmt.Errorf("could not create config directory: %v", err)
		}
	}

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(configPath)

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

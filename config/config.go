/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package config

import (
	"fmt"
	"github.com/spf13/viper"
	"os"
	"path/filepath"
)

const configTemplate = `api_keys:
  urlscan:
    api_key: your-urlscan-api-key

  ipinfo:
    api_key: your-ipinfo-api-key
`

func EnsureConfigExists() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not find home directory: %v", err)
	}

	configDir := filepath.Join(home, ".config", "soc-cli")
	configFile := filepath.Join(configDir, "config.yaml")

	// Create the directory if it doesn't exist
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, os.ModePerm); err != nil {
			return fmt.Errorf("could not create config directory: %v", err)
		}
	}

	// Create file with default config if doesn't exist
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		defaultConfig := []byte(configTemplate)
		if err := os.WriteFile(configFile, defaultConfig, 0644); err != nil {
			return fmt.Errorf("could not create config file: %v", err)
		}
		fmt.Println("A new configuration file was created at:", configFile)
	}

	return nil
}

func LoadConfig() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not find home directory: %v", err)
	}

	configPath := filepath.Join(home, ".config", "soc-cli")

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(configPath)

	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("error reading config file: %v", err)
	}

	return nil
}

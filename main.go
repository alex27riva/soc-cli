/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package main

import (
	"fmt"
	"github.com/spf13/viper"
	"log"
	"os"
	"path/filepath"
	"soc-cli/cmd"
)

func ensureConfigExists() error {
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

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		defaultConfig := []byte("# urlscan_api_key: your-urlscan-api-key\n")
		if err := os.WriteFile(configFile, defaultConfig, 0644); err != nil {
			return fmt.Errorf("could not create config file: %v", err)
		}
		fmt.Println("A new configuration file was created at:", configFile)
	}

	return nil
}

func loadConfig() error {
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

func main() {
	if err := ensureConfigExists(); err != nil {
		log.Fatalf("Error ensuring config exists: %v", err)
	}

	if err := loadConfig(); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	cmd.Execute()
}

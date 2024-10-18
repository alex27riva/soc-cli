/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package main

import (
	"log"
	"soc-cli/cmd"
	"soc-cli/config"
)

func main() {
	if err := config.EnsureConfigExists(); err != nil {
		log.Fatalf("Error ensuring config exists: %v", err)
	}

	if err := config.LoadConfig(); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	cmd.Execute()
}

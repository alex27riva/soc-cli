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
	if err := config.InitConfig(); err != nil {
		log.Fatalf("Error initializing config: %v", err)
	}

	cmd.Execute()
}

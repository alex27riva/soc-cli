/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"soc-cli/internal/apis"
)

func displayData(domainInfo apis.DomainInfo) {

	fmt.Println("Domain Information:")
	fmt.Printf("Domain Name: %s\n", domainInfo.Domain.Domain)
	fmt.Printf("Domain ID: %s\n", domainInfo.Domain.ID)
	fmt.Printf("Extension: %s\n", domainInfo.Domain.Extension)
	fmt.Printf("Whois Server: %s\n", domainInfo.Domain.WhoisServer)
	fmt.Printf("Status: %v\n", domainInfo.Domain.Status)
	fmt.Printf("Created Date: %s\n", domainInfo.Domain.CreatedDate)
	fmt.Printf("Updated Date: %s\n", domainInfo.Domain.UpdatedDate)
	fmt.Printf("Expiration Date: %s\n", domainInfo.Domain.ExpirationDate)

	fmt.Println("\nRegistrar Information:")
	fmt.Printf("Registrar Name: %s\n", domainInfo.Registrar.Name)
	fmt.Printf("Registrar Phone: %s\n", domainInfo.Registrar.Phone)
	fmt.Printf("Registrar Email: %s\n", domainInfo.Registrar.Email)

	fmt.Println("\nRegistrant Information:")
	fmt.Printf("Registrant Name: %s\n", domainInfo.Registrant.Name)
	fmt.Printf("Registrant Organization: %s\n", domainInfo.Registrant.Organization)
	fmt.Printf("Registrant Country: %s\n", domainInfo.Registrant.Country)
	fmt.Printf("Registrant Email: %s\n", domainInfo.Registrant.Email)
}

var whoisCmd = &cobra.Command{
	Use:   "whois [domain]",
	Short: "Perform a WHOIS lookup on a domain",
	Long:  `Queries the who-dat.as93.net API to perform a WHOIS lookup on the specified domain.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]

		whoisData := apis.GetWhoisData(target)
		displayData(*whoisData)
	},
}

func init() {
	rootCmd.AddCommand(whoisCmd)
}

/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package apis

import (
	"fmt"

	"resty.dev/v3"
)

const whodatAPIURL = "https://who-dat.as93.net/%s"

// Domain represents the domain information
type Domain struct {
	ID                   string   `json:"id"`
	Domain               string   `json:"domain"`
	Punycode             string   `json:"punycode"`
	Name                 string   `json:"name"`
	Extension            string   `json:"extension"`
	WhoisServer          string   `json:"whois_server"`
	Status               []string `json:"status"`
	NameServers          []string `json:"name_servers"`
	CreatedDate          string   `json:"created_date"`
	CreatedDateInTime    string   `json:"created_date_in_time"`
	UpdatedDate          string   `json:"updated_date"`
	UpdatedDateInTime    string   `json:"updated_date_in_time"`
	ExpirationDate       string   `json:"expiration_date"`
	ExpirationDateInTime string   `json:"expiration_date_in_time"`
}

// Registrar represents the registrar information
type Registrar struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Phone       string `json:"phone"`
	Email       string `json:"email"`
	ReferralURL string `json:"referral_url"`
}

// Contact represents the contact information (registrant, administrative, technical)
type Contact struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Organization string `json:"organization"`
	Street       string `json:"street"`
	City         string `json:"city"`
	Province     string `json:"province"`
	PostalCode   string `json:"postal_code"`
	Country      string `json:"country"`
	Phone        string `json:"phone"`
	Email        string `json:"email"`
}

// DomainInfo represents the entire structure of the JSON
type DomainInfo struct {
	Domain         Domain    `json:"domain"`
	Registrar      Registrar `json:"registrar"`
	Registrant     Contact   `json:"registrant"`
	Administrative Contact   `json:"administrative"`
	Technical      Contact   `json:"technical"`
}

func GetWhoisData(domain string) (*DomainInfo, error) {
	apiUrl := fmt.Sprintf(whodatAPIURL, domain)

	result := &DomainInfo{}

	client := resty.New()
	defer client.Close()

	_, err := client.R().
		SetResult(result).
		Get(apiUrl)

	return result, err
}

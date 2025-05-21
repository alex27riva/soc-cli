/*
Copyright © 2025 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package apis

// Define the structs to match the JSON structure
type VTResponse struct {
	Data Data `json:"data"`
}

type Data struct {
	ID         string     `json:"id"`
	Type       string     `json:"type"`
	Links      Links      `json:"links"`
	Attributes Attributes `json:"attributes"`
}

type Links struct {
	Self string `json:"self"`
}

type Attributes struct {
	Reputation           int               `json:"reputation"`
	LastModificationDate int64             `json:"last_modification_date"`
	Magic                string            `json:"magic"`
	Ssdeep               string            `json:"ssdeep"`
	MeaningfulName       string            `json:"meaningful_name"`
	TypeDescription      string            `json:"type_description"`
	Vhash                string            `json:"vhash"`
	Sha256               string            `json:"sha256"`
	TypeTags             []string          `json:"type_tags"`
	TimesSubmitted       int               `json:"times_submitted"`
	LastAnalysisStats    LastAnalysisStats `json:"last_analysis_stats"`
	TypeExtension        string            `json:"type_extension"`
	TypeTag              string            `json:"type_tag"`
	LastSubmissionDate   int64             `json:"last_submission_date"`
	Sha1                 string            `json:"sha1"`
}

type LastAnalysisStats struct {
	Malicious        int `json:"malicious"`
	Suspicious       int `json:"suspicious"`
	Undetected       int `json:"undetected"`
	Harmless         int `json:"harmless"`
	Timeout          int `json:"timeout"`
	ConfirmedTimeout int `json:"confirmed-timeout"`
	Failure          int `json:"failure"`
	TypeUnsupported  int `json:"type-unsupported"`
}

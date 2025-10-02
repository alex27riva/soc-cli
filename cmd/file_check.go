/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"soc-cli/internal/apis"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"resty.dev/v3"
)

const virusTotalBaseURL = "https://www.virustotal.com/api/v3"
const virusTotalFileGuiURL = "https://www.virustotal.com/gui/file/%s"
const virusTotalFileReportEndpoint = "/files/"
const virusTotalFileUploadEndpoint = "/files"

// fileCheckCmd represents the file-check command
var fileCheckCmd = &cobra.Command{
	Use:   "file-check [file]",
	Short: "Check file for suspicious content and upload to VirusTotal if not present",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]
		checkFileOnVirusTotal(filePath)
	},
}

func init() {
	rootCmd.AddCommand(fileCheckCmd)
}

func checkFileOnVirusTotal(filePath string) {
	apiKey := viper.GetString("api_keys.virustotal.api_key")
	if apiKey == "" {
		color.Red("VirusTotal API key missing! Please set it in the config file.")
		os.Exit(1)
	}

	hash, err := calculateSHA256(filePath)
	if err != nil {
		color.Red("Error calculating file hash: %v", err)
		os.Exit(1)
	}

	fmt.Printf("File SHA256: %s\n", hash)

	// Check if file already exists in VirusTotal
	if exist, report := fileExistsInVirusTotal(apiKey, hash); exist {
		color.Green("File already analyzed on VirusTotal.")
		displayVirusTotalReport(report)

	} else {
		// Ask for confirmation before uploading
		if confirmUpload() {
			fmt.Println("Uploading file to VirusTotal for analysis...")
			uploadFileToVirusTotal(apiKey, filePath)
		} else {
			fmt.Println("Upload canceled.")
		}
	}
}

func confirmUpload() bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("File not found on VirusTotal. Do you want to upload it for analysis? (y/N): ")
	response, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("Error reading input: %v", err)
	}
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

func calculateSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("could not open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("could not hash file: %w", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func fileExistsInVirusTotal(apiKey, hash string) (exist bool, report apis.VTResponse) {

	apiUrl := virusTotalBaseURL + virusTotalFileReportEndpoint + hash
	headers := map[string]string{
		"X-Apikey": apiKey,
		"Accept":   "application/json",
	}

	client := resty.New()
	defer client.Close()

	res, err := client.R().
		SetHeaders(headers).
		SetResult(report).
		Get(apiUrl)
	if err != nil {
		log.Fatalf("Error fetching VirusTotal: %v", err)
	}

	if res.StatusCode() == http.StatusNotFound {
		return false, apis.VTResponse{} // File not found on VirusTotal
	}

	return true, report
}

func uploadFileToVirusTotal(apiKey, filePath string) {

	// Create a buffer to hold the multipart form data
	var b bytes.Buffer
	writer := multipart.NewWriter(&b)

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Could not open file for upload: %v", err)
	}
	defer file.Close()

	part, err := writer.CreateFormFile("file", filePath)
	if err != nil {
		log.Fatalf("CreateFormFile: %v", err)
	}

	// Copy the file content to the form file field
	_, err = io.Copy(part, file)
	if err != nil {
		log.Fatalf("io.Copy: %v", err)
	}

	// Close the writer to finalize the multipart form
	err = writer.Close()
	if err != nil {
		log.Fatalf("writer.Close: %v", err)
	}

	req, err := http.NewRequest("POST", virusTotalBaseURL+virusTotalFileUploadEndpoint, &b)
	if err != nil {
		log.Fatalf("Error creating upload request: %v", err)
	}
	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error uploading file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Unexpected response from VirusTotal upload: %v", req)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading upload response body: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		log.Fatalf("Error parsing upload response JSON: %v", err)
	}

	// Extract the File ID for querying the report
	fileID, ok := result["data"].(map[string]interface{})["id"].(string)
	if !ok {
		log.Fatalf("File ID not found in response")
	}
	fmt.Println("File uploaded successfully. Fetching scan report...")
	fetchVirusTotalReport(apiKey, fileID)
}

func fetchVirusTotalReport(apiKey, fileID string) {
	client := &http.Client{}
	url := fmt.Sprintf("%s%s%s", virusTotalBaseURL, virusTotalFileReportEndpoint, fileID)

	for attempts := 0; attempts < 10; attempts++ {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Fatalf("Error creating request: %v", err)
		}
		req.Header.Set("x-apikey", apiKey)
		req.Header.Set("accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Error making request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			fmt.Println("Report not ready. Retrying in 10 seconds...")
			time.Sleep(10 * time.Second)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			log.Fatalf("Unexpected response from VirusTotal report API: %v", resp)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("Error reading response body: %v", err)
		}

		var result apis.VTResponse
		if err := json.Unmarshal(body, &result); err != nil {
			log.Fatalf("Error parsing JSON response: %v", err)
		}
		displayVirusTotalReport(result)
		fmt.Println("VirusTotal Scan Report:")
		return
	}

	color.Red("Report could not be retrieved within the timeout period.")
}

func displayVirusTotalReport(report apis.VTResponse) {
	scanUrl := fmt.Sprintf(virusTotalFileGuiURL, report.Data.Attributes.Sha256)

	color.Blue("VirusTotal Scan Report:")

	fmt.Printf("\nType: %s\n", report.Data.Type)
	fmt.Printf("Meaningful Name: %s\n", report.Data.Attributes.MeaningfulName)
	fmt.Printf("Magic: %v\n", report.Data.Attributes.Magic)
	fmt.Printf("Reputation: %d\n", report.Data.Attributes.Reputation)
	fmt.Printf("Link: %s\n", scanUrl)
	fmt.Printf("Analysis result: malicious %v, undetected %v, harmless %v\n", report.Data.Attributes.LastAnalysisStats.Malicious, report.Data.Attributes.LastAnalysisStats.Suspicious, report.Data.Attributes.LastAnalysisStats.Harmless)
}

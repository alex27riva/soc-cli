/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	vt "github.com/VirusTotal/vt-go"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"soc-cli/internal/util"
)

const virusTotalFileGuiURL = "https://www.virustotal.com/gui/file/%s"

// fileCheckCmd represents the file-check command
var fileCheckCmd = &cobra.Command{
	Use:   "file-check [file]",
	Short: "Scan a file for threats using VirusTotal",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		checkFileOnVirusTotal(args[0])
	},
}

func init() {
	rootCmd.AddCommand(fileCheckCmd)
}

func checkFileOnVirusTotal(filePath string) {
	apiKey := viper.GetString("api_keys.virustotal.api_key")
	if apiKey == "" {
		util.PrintError("VirusTotal API key missing! Please set it in the config file.")
		os.Exit(1)
	}

	hash, err := calculateSHA256(filePath)
	if err != nil {
		util.PrintError("Error calculating file hash: %v", err)
		os.Exit(1)
	}

	util.PrintEntry("File SHA256", hash)

	client := vt.NewClient(apiKey)

	fileObj, err := client.GetObject(vt.URL("files/%s", hash))
	if err != nil {
		if vtErr, ok := err.(vt.Error); ok && vtErr.Code == "NotFoundError" {
			if confirmUpload() {
				uploadAndReport(client, filePath, hash)
			} else {
				fmt.Println("Upload canceled.")
			}
			return
		}
		log.Fatalf("Error querying VirusTotal: %v", err)
	}

	util.PrintSuccess("File already analyzed on VirusTotal.")
	displayVirusTotalReport(fileObj)
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

func uploadAndReport(client *vt.Client, filePath, hash string) {
	f, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Could not open file for upload: %v", err)
	}
	defer f.Close()

	util.PrintHeader("Uploading file to VirusTotal for analysis...")
	scanner := client.NewFileScanner()
	analysis, err := scanner.ScanFile(f, nil)
	if err != nil {
		log.Fatalf("Error uploading file: %v", err)
	}

	analysisID := analysis.ID()
	util.PrintHeader("File uploaded. Waiting for analysis to complete...")

	for attempts := 0; attempts < 10; attempts++ {
		time.Sleep(15 * time.Second)

		analysisObj, err := client.GetObject(vt.URL("analyses/%s", analysisID))
		if err != nil {
			log.Fatalf("Error fetching analysis status: %v", err)
		}

		status, _ := analysisObj.GetString("status")
		if status == "completed" {
			fileObj, err := client.GetObject(vt.URL("files/%s", hash))
			if err != nil {
				log.Fatalf("Error fetching file report: %v", err)
			}
			displayVirusTotalReport(fileObj)
			return
		}

		fmt.Printf("Analysis status: %s. Retrying in 15 seconds...\n", status)
	}

	util.PrintError("Report could not be retrieved within the timeout period.")
}

func displayVirusTotalReport(file *vt.Object) {
	sha256Hash, _ := file.GetString("sha256")
	meaningfulName, _ := file.GetString("meaningful_name")
	magic, _ := file.GetString("magic")
	reputation, _ := file.GetInt64("reputation")
	malicious, _ := file.GetInt64("last_analysis_stats.malicious")
	suspicious, _ := file.GetInt64("last_analysis_stats.suspicious")
	harmless, _ := file.GetInt64("last_analysis_stats.harmless")

	verdict := fmt.Sprintf("malicious %d, suspicious %d, harmless %d", malicious, suspicious, harmless)
	if malicious > 0 {
		verdict = color.RedString(verdict)
	} else {
		verdict = color.GreenString(verdict)
	}

	util.PrintHeader("\nVirusTotal Scan Report:")
	util.PrintEntry("Type", file.Type())
	util.PrintEntry("Meaningful Name", meaningfulName)
	util.PrintEntry("Magic", magic)
	util.PrintEntry("Reputation", int(reputation))
	util.PrintEntry("Link", fmt.Sprintf(virusTotalFileGuiURL, sha256Hash))
	util.PrintEntry("Analysis", verdict)
}

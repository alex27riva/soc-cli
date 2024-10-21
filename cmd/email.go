/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"soc-cli/internal/util"
	"strings"
)

var analyzeEmailCmd = &cobra.Command{
	Use:   "email [file]",
	Short: "Analyze an email in .eml format for attachments and links",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]
		analyzeEmail(filePath)
	},
}

func init() {
	rootCmd.AddCommand(analyzeEmailCmd)
}

// analyzeEmail processes the .eml file and extracts attachments and links
func analyzeEmail(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// Parse the email message
	msg, err := mail.ReadMessage(file)
	if err != nil {
		fmt.Println("Error parsing .eml file:", err)
		return
	}
	color.Blue("Main information:")
	fmt.Println("From:", msg.Header.Get("From"))
	fmt.Println("To:", msg.Header.Get("To"))
	fmt.Println("Subject:", msg.Header.Get("Subject"))
	fmt.Println("Date:", msg.Header.Get("Date"))
	fmt.Println("Return-Path:", msg.Header.Get("Return-Path"))

	// Check for SPF information
	spfHeader := msg.Header.Get("Received-SPF")
	if spfHeader != "" {
		fmt.Println(color.BlueString("\nSPF Information:\n"), spfHeader)
	} else {
		fmt.Println(color.BlueString("\nSPF Information:\n") + "No Received-SPF header found.")
	}

	// Extract DKIM Information
	dkimHeader := msg.Header.Get("DKIM-Signature")
	if dkimHeader != "" {
		color.Blue("\nDKIM Information:")
		fmt.Println(dkimHeader)
	} else {
		fmt.Println(color.BlueString("\nDKIM Information:\n") + "No DKIM-Signature header found.")
	}

	// Extract DMARC Information from Authentication-Results header
	authResults := msg.Header.Get("Authentication-Results")
	if authResults != "" {
		extractDMARCDKIM(authResults)
	} else {
		fmt.Println("\nDMARC Information: No Authentication-Results header found.")
	}

	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		fmt.Println("Error parsing content type:", err)
		return
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		// Handle multipart emails (usually contains attachments and text)
		mr := multipart.NewReader(msg.Body, params["boundary"])
		processMultipart(mr)
	} else {
		// Handle single-part emails (just extract links)
		body, _ := io.ReadAll(msg.Body)
		extractLinks(string(body))
	}
}

// processMultipart processes multipart emails for attachments and links
func processMultipart(mr *multipart.Reader) {
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println("Error reading part:", err)
			return
		}

		contentType := part.Header.Get("Content-Type")
		disposition := part.Header.Get("Content-Disposition")

		// If it's an attachment, list it
		if strings.Contains(disposition, "attachment") {
			fileName := part.FileName()
			if fileName == "" {
				fileName = "unnamed attachment"
			}
			fmt.Printf("Attachment: %s (MIME type: %s)\n", fileName, contentType)
		} else {
			// Otherwise, it's likely part of the email body (text or HTML)
			body, _ := io.ReadAll(part)
			extractLinks(string(body))
		}
	}
}

// extractDMARCDKIM extracts DMARC and DKIM results from the Authentication-Results header
func extractDMARCDKIM(authResults string) {
	color.Blue("\nAuthentication Results:")
	fmt.Println(authResults)

	// Check for DKIM result
	if strings.Contains(authResults, "dkim=pass") {
		fmt.Println("DKIM:", color.GreenString("pass"))
	} else if strings.Contains(authResults, "dkim=fail") {
		fmt.Println("DKIM:", color.RedString("fail"))
	} else {
		fmt.Println("DKIM: No DKIM result found.")
	}

	// Check for DMARC result
	if strings.Contains(authResults, "dmarc=pass") {
		fmt.Println("DMARC:", color.GreenString("pass"))
	} else if strings.Contains(authResults, "dmarc=fail") {
		fmt.Println("DMARC:", color.RedString("fail"))
	} else {
		fmt.Println("DMARC: No DMARC result found.")
	}
}

// extractLinks extracts URLs from email body text or HTML
func extractLinks(body string) {
	links := util.URLRegex.FindAllString(body, -1)

	if len(links) > 0 {
		color.Blue("\nLinks found in the email:")
		for _, link := range links {
			fmt.Println("-", link)
		}
	} else {
		color.Blue("\nNo links found in the email.")
	}
}

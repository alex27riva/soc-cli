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
	"mime/quotedprintable"
	"net/mail"
	"os"
	"soc-cli/internal/util"
	"strings"
)

const (
	emlExtension                = ".eml"
	contentTypeHeader           = "Content-Type"
	transferEncodingHeader      = "Content-Transfer-Encoding"
	receivedSPFHeader           = "Received-SPF"
	dkimSignatureHeader         = "DKIM-Signature"
	authenticationResultsHeader = "Authentication-Results"
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
	if !isValidEmlFile(filePath) {
		return
	}

	file, err := os.Open(filePath)
	if err != nil {
		util.PrintError("Error opening file: %v", err)
		return
	}
	defer file.Close()

	// Parse the email message
	msg, err := mail.ReadMessage(file)
	if err != nil {
		util.PrintError("Error parsing .eml file: %v", err)
		return
	}

	printEmailHeaders(msg)

	// Check for SPF information
	printHeaderInfo(msg.Header.Get(receivedSPFHeader), "SPF Information")

	// Extract DKIM Information
	printHeaderInfo(msg.Header.Get(dkimSignatureHeader), "DKIM Information")

	// Extract DMARC Information from Authentication-Results header
	authResults := msg.Header.Get(authenticationResultsHeader)
	if authResults != "" {
		extractDMARCDKIM(authResults)
	} else {
		util.PrintHeader("\nAuthentication Results:")
		fmt.Println("No Authentication-Results header found.")
	}

	processEmailBody(msg)
}

// isValidEmlFile checks if the provided file path has a valid .eml extension
func isValidEmlFile(filePath string) bool {
	if !strings.HasSuffix(strings.ToLower(filePath), emlExtension) {
		util.PrintError("The provided file is not an .eml file.")
		return false
	}
	return true
}

// processEmailBody processes the email body based on its content type
func processEmailBody(msg *mail.Message) {
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get(contentTypeHeader))
	handleError(err, "Error parsing content type:")

	if strings.HasPrefix(mediaType, "multipart/") {
		mr := multipart.NewReader(msg.Body, params["boundary"])
		processMultipart(mr)
	} else {
		handleSinglePartEmail(msg)
	}
}

// handleSinglePartEmail handles single-part emails and extracts links
func handleSinglePartEmail(msg *mail.Message) {
	body, _ := io.ReadAll(msg.Body)
	encoding := msg.Header.Get(transferEncodingHeader)

	if strings.ToLower(encoding) == "quoted-printable" {
		reader := quotedprintable.NewReader(strings.NewReader(string(body)))
		decodedBody, err := io.ReadAll(reader)
		handleError(err, "Error decoding quoted-printable content:")
		extractLinks(string(decodedBody))
	} else {
		extractLinks(string(body))
	}
}

// processMultipart processes multipart emails for attachments and links
func processMultipart(mr *multipart.Reader) {
	attachmentsFound := false
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			util.PrintError("Error reading part: %v", err)
			return
		}

		contentType := part.Header.Get(contentTypeHeader)
		disposition := part.Header.Get("Content-Disposition")

		// If it's an attachment, list it
		if strings.Contains(disposition, "attachment") {
			if !attachmentsFound {
				util.PrintHeader("\nAttachments:")
				attachmentsFound = true
			}
			handleAttachment(part, contentType)
		} else {
			// Otherwise, it's likely part of the email body (text or HTML)
			body, _ := io.ReadAll(part)
			extractLinks(string(body))
		}
	}
	if !attachmentsFound {
		fmt.Println("\nNo attachments found.")
	}
}

// extractDMARCDKIM extracts DMARC and DKIM results from the Authentication-Results header
func extractDMARCDKIM(authResults string) {
	util.PrintHeader("\nAuthentication Results:")

	// Check for DKIM result
	if strings.Contains(authResults, "dkim=pass") {
		util.PrintEntry("DKIM", color.GreenString("pass"))
	} else if strings.Contains(authResults, "dkim=fail") {
		util.PrintEntry("DKIM", color.RedString("fail"))
	} else {
		util.PrintEntry("DKIM", "no result found")
	}

	// Check for DMARC result
	if strings.Contains(authResults, "dmarc=pass") {
		util.PrintEntry("DMARC", color.GreenString("pass"))
	} else if strings.Contains(authResults, "dmarc=fail") {
		util.PrintEntry("DMARC", color.RedString("fail"))
	} else {
		util.PrintEntry("DMARC", "no result found")
	}
}

// extractLinks extracts URLs from email body text or HTML
func extractLinks(body string) {
	links := util.URLRegex.FindAllString(body, -1)

	if len(links) > 0 {
		util.PrintHeader("\nLinks found in the email:")
		for _, link := range links {
			fmt.Println("-", link)
		}
	} else {
		util.PrintHeader("\nNo links found in the email.")
	}
}

func handleAttachment(part *multipart.Part, contentType string) {
	fileName := part.FileName()
	if fileName == "" {
		fileName = "unnamed attachment"
	}

	util.PrintEntry("Attachment", fmt.Sprintf("%s (%s)", fileName, contentType))
}

func handleError(err error, message string) {
	if err != nil {
		util.PrintError("%s %v", message, err)
	}
}

func printHeader(headerName, headerValue string) {
	if headerValue != "" {
		fmt.Printf("%s: %s\n", color.CyanString(headerName), headerValue)
	}
}

func printEmailHeaders(msg *mail.Message) {
	util.PrintHeader("Main information:")
	printHeader("From", msg.Header.Get("From"))
	printHeader("To", msg.Header.Get("To"))
	printHeader("Cc", msg.Header.Get("Cc"))
	printHeader("Bcc", msg.Header.Get("Bcc"))
	printHeader("Subject", msg.Header.Get("Subject"))
	printHeader("Date", msg.Header.Get("Date"))
	printHeader("Reply-To", msg.Header.Get("Reply-To"))
	printHeader("Return-Path", msg.Header.Get("Return-Path"))
}

func printHeaderInfo(headerValue, headerName string) {
	util.PrintHeader("\n%s:", headerName)
	if headerValue != "" {
		fmt.Println(headerValue)
	} else {
		fmt.Println("No information found.")
	}
}

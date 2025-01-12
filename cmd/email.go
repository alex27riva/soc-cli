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
		fmt.Println("\nDMARC Information: No Authentication-Results header found.")
	}

	processEmailBody(msg)
}

// isValidEmlFile checks if the provided file path has a valid .eml extension
func isValidEmlFile(filePath string) bool {
	if !strings.HasSuffix(strings.ToLower(filePath), emlExtension) {
		color.Red("The provided file is not an .eml file.")
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
			fmt.Println("Error reading part:", err)
			return
		}

		contentType := part.Header.Get(contentTypeHeader)
		disposition := part.Header.Get("Content-Disposition")

		// If it's an attachment, list it
		if strings.Contains(disposition, "attachment") {
			if !attachmentsFound {
				color.Blue("\nAttachments:")
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

func handleAttachment(part *multipart.Part, contentType string) {
	fileName := part.FileName()
	if fileName == "" {
		fileName = "unnamed attachment"
	}

	fmt.Printf("Attachment: %s (MIME type: %s)\n", fileName, contentType)
}

func handleError(err error, message string) {
	if err != nil {
		fmt.Println(message, err)
	}
}

func printEmailHeaders(msg *mail.Message) {
	color.Blue("Main information:")
	fmt.Println("From:", msg.Header.Get("From"))
	fmt.Println("To:", msg.Header.Get("To"))
	fmt.Println("Subject:", msg.Header.Get("Subject"))
	fmt.Println("Date:", msg.Header.Get("Date"))
	fmt.Println("Return-Path:", msg.Header.Get("Return-Path"))
}

func printHeaderInfo(headerValue, headerName string) {
	if headerValue != "" {
		fmt.Println(color.BlueString("\n%s:\n", headerName), headerValue)
	} else {
		fmt.Println(color.BlueString("\n%s:\n", headerName) + "No information found.")
	}
}

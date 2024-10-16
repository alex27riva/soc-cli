/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
    "fmt"
    "io"
    "mime"
    "mime/multipart"
    "net/mail"
    "os"
    "strings"
    "github.com/spf13/cobra"
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

    fmt.Println("Subject:", msg.Header.Get("Subject"))
    fmt.Println("From:", msg.Header.Get("From"))
    fmt.Println("To:", msg.Header.Get("To"))

	// Check for SPF information
	spfHeader := msg.Header.Get("Received-SPF")
	if spfHeader != "" {
		fmt.Println("\nSPF Information:", spfHeader)
	} else {
		fmt.Println("\nSPF Information: No Received-SPF header found.")
	}

    // Extract DKIM Information
    dkimHeader := msg.Header.Get("DKIM-Signature")
    if dkimHeader != "" {
        fmt.Println("\nDKIM Information:")
        fmt.Println(dkimHeader)
    } else {
        fmt.Println("\nDKIM Information: No DKIM-Signature header found.")
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
    fmt.Println("\nAuthentication Results:")
    fmt.Println(authResults)

    // Check for DKIM result
    if strings.Contains(authResults, "dkim=pass") {
        fmt.Println("DKIM: pass")
    } else if strings.Contains(authResults, "dkim=fail") {
        fmt.Println("DKIM: fail")
    } else {
        fmt.Println("DKIM: No DKIM result found.")
    }

    // Check for DMARC result
    if strings.Contains(authResults, "dmarc=pass") {
        fmt.Println("DMARC: pass")
    } else if strings.Contains(authResults, "dmarc=fail") {
        fmt.Println("DMARC: fail")
    } else {
        fmt.Println("DMARC: No DMARC result found.")
    }
}


// extractLinks extracts URLs from email body text or HTML
func extractLinks(body string) {
    links := URLRegex.FindAllString(body, -1)

    if len(links) > 0 {
        fmt.Println("\nLinks found in the email:")
        for _, link := range links {
            fmt.Println("-", link)
        }
    } else {
        fmt.Println("\nNo links found in the email.")
    }
}

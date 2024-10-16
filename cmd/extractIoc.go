/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
    "bufio"
    "fmt"
    "log"
    "os"
    "github.com/spf13/cobra"
)

var extractIocCmd = &cobra.Command{
    Use:   "extract-ioc [file]",
    Short: "Extract Indicators of Compromise (IOCs) from a file",
    Long:  `Extracts IOCs like URLs, IP addresses, email addresses, and file hashes from a specified text file.`,
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        filePath := args[0]
        extractIOCs(filePath)
    },
}

func init() {
    rootCmd.AddCommand(extractIocCmd)
}

func extractIOCs(filePath string) {
    file, err := os.Open(filePath)
    if err != nil {
        log.Fatalf("Could not open file: %v", err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    
    // Maps to store unique IOCs
    uniqueIPs := make(map[string]struct{})
    uniqueURLs := make(map[string]struct{})
    uniqueEmails := make(map[string]struct{})
    uniqueSHA256 := make(map[string]struct{})
    
    // Scan the file line by line and extract IOCs
    for scanner.Scan() {
        line := scanner.Text()
        
        // Extract and store unique IPs
        ips := IPRegex.FindAllString(line, -1)
        for _, ip := range ips {
            uniqueIPs[ip] = struct{}{}
        }

        // Extract and store unique URLs
        urls := URLRegex.FindAllString(line, -1)
        for _, url := range urls {
            uniqueURLs[url] = struct{}{}
        }

        // Extract and store unique Emails
        emails := EmailRegex.FindAllString(line, -1)
        for _, email := range emails {
            uniqueEmails[email] = struct{}{}
        }

        // Extract and store unique SHA256 hashes
        sha256Hashes := SHA256Regex.FindAllString(line, -1)
        for _, hash := range sha256Hashes {
            uniqueSHA256[hash] = struct{}{}
        }
    }

    if err := scanner.Err(); err != nil {
        log.Fatalf("Error reading file: %v", err)
    }

    // Print IOCs grouped by type
    fmt.Println(Magenta + "Extracted IOCs:" + Reset)

    // Print IPs
    if len(uniqueIPs) > 0 {
        fmt.Println(Green + "\nIP Addresses:" + Reset)
        for ip := range uniqueIPs {
            fmt.Println(ip)
        }
    }

    // Print URLs
    if len(uniqueURLs) > 0 {
        fmt.Println(Green + "\nURLs:" + Reset)
        for url := range uniqueURLs {
            fmt.Println(url)
        }
    }

    // Print Emails
    if len(uniqueEmails) > 0 {
        fmt.Println(Green + "\nEmail Addresses:" + Reset)
        for email := range uniqueEmails {
            fmt.Println(email)
        }
    }

    // Print SHA256 Hashes
    if len(uniqueSHA256) > 0 {
        fmt.Println(Green + "\nSHA256 Hashes:" + Reset)
        for hash := range uniqueSHA256 {
            fmt.Println(hash)
        }
    }
}
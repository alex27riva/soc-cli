/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package util

import (
	"fmt"
	"time"
)

// Remove duplicates from a slice
func RemoveDuplicates(items []string) []string {
	uniqueItems := make(map[string]bool)
	result := []string{}
	for _, item := range items {
		if !uniqueItems[item] {
			uniqueItems[item] = true
			result = append(result, item)
		}
	}
	return result
}

// Shorten string to given length
func ShortStr(s string, maxLength int) string {
	if len(s) > maxLength {
		return s[:maxLength]
	}
	return s
}

func HumanReadableDate(dateString string) (string, error) {
	layout := time.RFC3339
	parsedTime, err := time.Parse(layout, dateString)
	if err != nil {
		return "", err
	}

	now := time.Now()
	diff := now.Sub(parsedTime)
	return formatDuration(diff), nil
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	weeks := days / 7

	if weeks > 0 {
		return fmt.Sprintf("%d weeks ago", weeks)
	}
	if days > 0 {
		return fmt.Sprintf("%d days ago", days)
	}
	hours := int(d.Hours())
	if hours > 0 {
		return fmt.Sprintf("%d hours ago", hours)
	}
	minutes := int(d.Minutes())
	if minutes > 0 {
		return fmt.Sprintf("%d minutes ago", minutes)
	}
	return "just now"
}

func IsValidDomain(domain string) bool {
	return DomainRegex.MatchString(domain)
}

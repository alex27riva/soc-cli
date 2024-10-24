/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package logic

import (
	"regexp"
	"strings"
)

func Defang(input string) string {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if emailRegex.MatchString(input) {
		return DefangEmail(input)
	}

	return DefangURL(input)
}

func DefangEmail(email string) string {
	defanged := strings.Replace(email, "@", "[at]", 1)
	defanged = strings.Replace(defanged, ".", "[.]", -1)

	return defanged
}

func DefangURL(url string) string {
	defanged := strings.Replace(url, "http://", "hxxp://", 1)
	defanged = strings.Replace(defanged, "https://", "hxxps://", 1)
	defanged = strings.Replace(defanged, ".", "[.]", -1)

	return defanged
}

// fang reverses the defanged URLs or email addresses
func Fang(input string) string {
	// Replace 'hxxp' or 'hxxps' with 'http' or 'https'
	fanged := strings.Replace(input, "hxxp", "http", -1)
	fanged = strings.Replace(fanged, "hxxps", "https", -1)

	// Replace '[.]' back to '.'
	fanged = strings.Replace(fanged, "[.]", ".", -1)

	// Replace '[at]' or similar with '@' for email addresses
	fanged = strings.Replace(fanged, "[at]", "@", -1)
	fanged = strings.Replace(fanged, "(at)", "@", -1)
	fanged = strings.Replace(fanged, "[@]", "@", -1)

	return fanged
}

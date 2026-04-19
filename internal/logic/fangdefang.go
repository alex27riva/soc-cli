/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package logic

import (
	"strings"

	"soc-cli/internal/util"
)

func Defang(input string) string {
	// Fang first so defanging an already-defanged input is a no-op.
	normalized := Fang(input)

	if loc := util.EmailRegex.FindStringIndex(normalized); loc != nil && loc[0] == 0 && loc[1] == len(normalized) {
		return DefangEmail(normalized)
	}

	return DefangURL(normalized)
}

func DefangEmail(email string) string {
	defanged := strings.Replace(email, "@", "[at]", 1)
	defanged = strings.ReplaceAll(defanged, ".", "[.]")

	return defanged
}

func DefangURL(url string) string {
	defanged := strings.Replace(url, "https://", "hxxps://", 1)
	defanged = strings.Replace(defanged, "http://", "hxxp://", 1)
	defanged = strings.ReplaceAll(defanged, ".", "[.]")

	return defanged
}

// Fang reverses the defanged URLs or email addresses.
func Fang(input string) string {
	fanged := strings.ReplaceAll(input, "hxxps", "https")
	fanged = strings.ReplaceAll(fanged, "hxxp", "http")
	fanged = strings.ReplaceAll(fanged, "[.]", ".")
	fanged = strings.ReplaceAll(fanged, "[at]", "@")
	fanged = strings.ReplaceAll(fanged, "(at)", "@")
	fanged = strings.ReplaceAll(fanged, "[@]", "@")

	return fanged
}

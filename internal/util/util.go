/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package util

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

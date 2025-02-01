/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package util

import (
	"fmt"
	"github.com/fatih/color"
)

func PrintEntry(entryName string, entryValue interface{}) {
	if entryValue != nil {
		switch v := entryValue.(type) {
		case string:
			if v != "" {
				fmt.Printf("%s: %s\n", color.CyanString(entryName), v)
			}
		case bool:
			fmt.Printf("%s: %t\n", color.CyanString(entryName), v)
		case int:
			fmt.Printf("%s: %d\n", color.CyanString(entryName), v)
		default:
			fmt.Printf("%s: %v\n", color.CyanString(entryName), v)
		}
	}
}

func PrintYesNo(val bool) string {
	if val {
		return color.GreenString("YES")
	}
	return color.RedString("NO")
}

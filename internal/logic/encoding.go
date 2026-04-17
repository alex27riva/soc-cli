/*
Copyright © 2026 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package logic

import (
	"encoding/base64"
	"net/url"
	"strings"
)

func Base64Encode(input string) string {
	return base64.StdEncoding.EncodeToString([]byte(input))
}

func Base64Decode(input string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func URLEncode(input string) string {
	// QueryEscape encodes spaces as '+'; swap to '%20'. Literal '+' in
	// input is already encoded as '%2B', so this replacement is safe.
	return strings.ReplaceAll(url.QueryEscape(input), "+", "%20")
}

func URLDecode(input string) (string, error) {
	return url.QueryUnescape(input)
}

/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"soc-cli/internal/util"
)

var (
	errNoExpClaim       = errors.New("no 'exp' claim in JWT")
	errInvalidExpFormat = errors.New("invalid 'exp' format")
	errTokenExpired     = errors.New("token expired")
)

// RFC 7519 registered claims, printed first in this order.
var standardJWTClaims = []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}

// Claims that carry Unix seconds and should render as timestamps.
var jwtTimestampClaims = map[string]bool{"exp": true, "nbf": true, "iat": true}

var jwtDecodeCmd = &cobra.Command{
	Use:   "jwt [token]",
	Short: "Decode a JWT and optionally check if it's expired",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		checkExpired, _ := cmd.Flags().GetBool("expired")
		asJSON, _ := cmd.Flags().GetBool("json")
		err := decodeJWT(args[0], checkExpired, asJSON)
		if errors.Is(err, errNoExpClaim) || errors.Is(err, errInvalidExpFormat) || errors.Is(err, errTokenExpired) {
			os.Exit(1)
		}
		return err
	},
}

func init() {
	jwtDecodeCmd.Flags().Bool("expired", false, "Check if the JWT is expired (exit with code 1 if true)")
	jwtDecodeCmd.Flags().Bool("json", false, "Output decoded JWT in JSON format")
	decodeCmd.AddCommand(jwtDecodeCmd)
}

func decodeJWT(token string, checkExpired, asJSON bool) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	var header, payload map[string]any
	if err := decodeJWTSegment(parts[0], &header); err != nil {
		return fmt.Errorf("error decoding header: %w", err)
	}
	if err := decodeJWTSegment(parts[1], &payload); err != nil {
		return fmt.Errorf("error decoding payload: %w", err)
	}

	if asJSON {
		out, err := json.MarshalIndent(map[string]any{
			"header":  header,
			"payload": payload,
		}, "", "  ")
		if err != nil {
			return fmt.Errorf("error marshaling JSON: %w", err)
		}
		fmt.Println(string(out))
	} else {
		util.PrintHeader("Header")
		printJWTClaims(header)
		util.PrintHeader("\nPayload")
		printJWTClaims(payload)
	}

	if checkExpired {
		return checkJWTExpiration(payload, asJSON)
	}
	return nil
}

func decodeJWTSegment(segment string, target *map[string]any) error {
	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

func printJWTClaims(claims map[string]any) {
	printed := make(map[string]bool, len(claims))
	for _, k := range standardJWTClaims {
		if v, ok := claims[k]; ok {
			util.PrintEntry(k, formatJWTClaim(k, v))
			printed[k] = true
		}
	}
	rest := make([]string, 0, len(claims))
	for k := range claims {
		if !printed[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		util.PrintEntry(k, formatJWTClaim(k, claims[k]))
	}
}

// formatJWTClaim renders Unix-second claims as "N (RFC3339)" and converts
// whole-number float64s (all JSON numbers decode to float64) to int64 so
// util.PrintEntry doesn't fall back to scientific notation.
func formatJWTClaim(key string, value any) any {
	f, isFloat := value.(float64)
	if !isFloat {
		return value
	}
	if jwtTimestampClaims[key] {
		t := time.Unix(int64(f), 0).Local()
		return fmt.Sprintf("%d (%s)", int64(f), t.Format(time.RFC3339))
	}
	if f == float64(int64(f)) {
		return int64(f)
	}
	return value
}

func checkJWTExpiration(payload map[string]any, asJSON bool) error {
	exp, ok := payload["exp"]
	if !ok {
		if !asJSON {
			util.PrintWarning("\nWarning: No 'exp' claim found in JWT.")
		}
		return errNoExpClaim
	}

	expFloat, ok := exp.(float64)
	if !ok {
		if !asJSON {
			util.PrintWarning("\nWarning: Invalid 'exp' format: %v", exp)
		}
		return errInvalidExpFormat
	}

	expTime := time.Unix(int64(expFloat), 0).Local()
	if time.Now().After(expTime) {
		if !asJSON {
			util.PrintError("\nToken expired at %s", expTime.Format(time.RFC3339))
		}
		return errTokenExpired
	}
	if !asJSON {
		util.PrintSuccess("\nToken is valid (expires at %s)", expTime.Format(time.RFC3339))
	}
	return nil
}

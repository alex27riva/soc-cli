package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var checkExpired bool

var jwtDecodeCmd = &cobra.Command{
	Use:   "jwt [token]",
	Short: "Decode a JWT and optionally check if it's expired",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		token := args[0]
		return DecodeJWT(token, checkExpired)
	},
}

func init() {
	jwtDecodeCmd.Flags().BoolVar(&checkExpired, "expired", false, "Check if the JWT is expired (exit with code 1 if true)")
	decodeCmd.AddCommand(jwtDecodeCmd)
}

func DecodeJWT(token string, checkExpired bool) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	decode := func(s string) ([]byte, error) {
		s = strings.ReplaceAll(s, "-", "+")
		s = strings.ReplaceAll(s, "_", "/")
		switch len(s) % 4 {
		case 2:
			s += "=="
		case 3:
			s += "="
		}
		return base64.StdEncoding.DecodeString(s)
	}

	// --- Decode header ---
	headerBytes, err := decode(parts[0])
	if err != nil {
		return fmt.Errorf("error decoding header: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("error parsing header JSON: %w", err)
	}

	// --- Decode payload ---
	payloadBytes, err := decode(parts[1])
	if err != nil {
		return fmt.Errorf("error decoding payload: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return fmt.Errorf("error parsing payload JSON: %w", err)
	}

	// --- Print ---
	headerJSON, _ := json.MarshalIndent(header, "", "  ")
	payloadJSON, _ := json.MarshalIndent(payload, "", "  ")

	fmt.Println("Header:")
	fmt.Println(string(headerJSON))
	fmt.Println("\nPayload:")
	fmt.Println(string(payloadJSON))
	fmt.Println("\nClaims:")
	for k, v := range payload {
		fmt.Printf("  %s: %v\n", k, v)
	}

	// --- Expiration check ---
	if checkExpired {
		exp, ok := payload["exp"]
		if !ok {
			fmt.Println("\n⚠️  No 'exp' claim found in JWT.")
			os.Exit(1)
		}

		var expTime time.Time
		switch val := exp.(type) {
		case float64:
			expTime = time.Unix(int64(val), 0)
		case int64:
			expTime = time.Unix(val, 0)
		default:
			fmt.Printf("\n⚠️  Invalid 'exp' format: %v\n", exp)
			os.Exit(1)
		}

		now := time.Now()
		if now.After(expTime) {
			fmt.Printf("\n❌ Token expired at %s (local time)\n", expTime.Local().Format(time.RFC3339))
			os.Exit(1)
		} else {
			fmt.Printf("\n✅ Token is valid (expires at %s)\n", expTime.Local().Format(time.RFC3339))
		}
	}

	return nil
}

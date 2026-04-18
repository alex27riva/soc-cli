/*
Copyright © 2026 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package cmd

import (
	"reflect"
	"strings"
	"testing"
)

func TestFormatJWTClaimTimestamp(t *testing.T) {
	got := formatJWTClaim("exp", float64(1704067200))
	s, ok := got.(string)
	if !ok {
		t.Fatalf("expected string, got %T (%v)", got, got)
	}
	if !strings.HasPrefix(s, "1704067200 (") {
		t.Errorf("expected prefix %q, got %q", "1704067200 (", s)
	}
	if !strings.HasSuffix(s, ")") {
		t.Errorf("expected trailing ')', got %q", s)
	}
}

func TestFormatJWTClaimTimestampKeys(t *testing.T) {
	for _, k := range []string{"exp", "iat", "nbf"} {
		got := formatJWTClaim(k, float64(1704067200))
		if _, ok := got.(string); !ok {
			t.Errorf("key %q: expected string, got %T", k, got)
		}
	}
}

func TestFormatJWTClaimWholeNumber(t *testing.T) {
	got := formatJWTClaim("version", float64(5))
	if got != int64(5) {
		t.Errorf("expected int64(5), got %v (%T)", got, got)
	}
}

func TestFormatJWTClaimFractional(t *testing.T) {
	got := formatJWTClaim("ratio", float64(1.5))
	if got != float64(1.5) {
		t.Errorf("expected 1.5, got %v (%T)", got, got)
	}
}

func TestFormatJWTClaimPassThrough(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value any
	}{
		{"string", "name", "Alice"},
		{"bool", "admin", true},
		{"slice", "roles", []any{"admin", "user"}},
		{"nil", "optional", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := formatJWTClaim(tc.key, tc.value)
			if !reflect.DeepEqual(got, tc.value) {
				t.Errorf("formatJWTClaim(%q, %v) = %v, want %v", tc.key, tc.value, got, tc.value)
			}
		})
	}
}

func TestDecodeJWTSegment(t *testing.T) {
	// base64url of {"alg":"HS256","typ":"JWT"}
	segment := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	var out map[string]any
	if err := decodeJWTSegment(segment, &out); err != nil {
		t.Fatalf("decodeJWTSegment: %v", err)
	}
	if out["alg"] != "HS256" {
		t.Errorf("alg = %v, want HS256", out["alg"])
	}
	if out["typ"] != "JWT" {
		t.Errorf("typ = %v, want JWT", out["typ"])
	}
}

func TestDecodeJWTSegmentInvalidBase64(t *testing.T) {
	var out map[string]any
	if err := decodeJWTSegment("!!!not base64!!!", &out); err == nil {
		t.Error("expected error for invalid base64, got nil")
	}
}

func TestDecodeJWTSegmentInvalidJSON(t *testing.T) {
	// base64url of "not json"
	var out map[string]any
	if err := decodeJWTSegment("bm90IGpzb24", &out); err == nil {
		t.Error("expected error for non-JSON payload, got nil")
	}
}

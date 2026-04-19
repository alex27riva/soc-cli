/*
Copyright © 2026 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package e2e_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func makeJWT(t *testing.T, header, payload map[string]any) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	p, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + ".sig"
}

// runSocAllowFail runs soc without fatal-ing on non-zero exit.
func runSocAllowFail(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	full := append([]string{"--config", configPath}, args...)
	cmd := exec.Command(binPath, full...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return outBuf.String(), errBuf.String(), ee.ExitCode()
		}
		t.Fatalf("unexpected error: %v", err)
	}
	return outBuf.String(), errBuf.String(), 0
}

func TestJWTDecodeDefault(t *testing.T) {
	tok := makeJWT(t,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{
			"iss":  "https://example.com",
			"sub":  "user123",
			"name": "Alice",
		})
	out := runSoc(t, "", "decode", "jwt", tok)
	for _, want := range []string{
		"Header", "alg: HS256", "typ: JWT",
		"Payload", "iss: https://example.com", "sub: user123", "name: Alice",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
}

func TestJWTDecodeJSON(t *testing.T) {
	tok := makeJWT(t,
		map[string]any{"alg": "HS256"},
		map[string]any{"sub": "user", "exp": float64(1704067200)})
	out := runSoc(t, "", "decode", "jwt", "--json", tok)
	var parsed struct {
		Header  map[string]any `json:"header"`
		Payload map[string]any `json:"payload"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if parsed.Header["alg"] != "HS256" {
		t.Errorf("header.alg = %v, want HS256", parsed.Header["alg"])
	}
	if parsed.Payload["sub"] != "user" {
		t.Errorf("payload.sub = %v, want user", parsed.Payload["sub"])
	}
	if parsed.Payload["exp"] != float64(1704067200) {
		t.Errorf("payload.exp = %v, want raw number 1704067200", parsed.Payload["exp"])
	}
}

func TestJWTDecodeInvalid(t *testing.T) {
	_, stderr, code := runSocAllowFail(t, "decode", "jwt", "notajwt")
	if code == 0 {
		t.Error("expected non-zero exit for invalid JWT")
	}
	if !strings.Contains(stderr, "invalid JWT") {
		t.Errorf("expected 'invalid JWT' in stderr; got: %s", stderr)
	}
}

func TestJWTExpiredTokenExitsOne(t *testing.T) {
	past := time.Now().Add(-time.Hour).Unix()
	tok := makeJWT(t,
		map[string]any{"alg": "HS256"},
		map[string]any{"sub": "user", "exp": float64(past)})
	_, _, code := runSocAllowFail(t, "decode", "jwt", "--expired", tok)
	if code != 1 {
		t.Errorf("expected exit 1 for expired token, got %d", code)
	}
}

func TestJWTValidTokenExitsZero(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()
	tok := makeJWT(t,
		map[string]any{"alg": "HS256"},
		map[string]any{"sub": "user", "exp": float64(future)})
	_, _, code := runSocAllowFail(t, "decode", "jwt", "--expired", tok)
	if code != 0 {
		t.Errorf("expected exit 0 for valid token, got %d", code)
	}
}

func TestJWTExpiredMissingClaim(t *testing.T) {
	tok := makeJWT(t,
		map[string]any{"alg": "HS256"},
		map[string]any{"sub": "user"})
	_, _, code := runSocAllowFail(t, "decode", "jwt", "--expired", tok)
	if code != 1 {
		t.Errorf("expected exit 1 when exp is missing, got %d", code)
	}
}

func TestJWTExpiredJSONStaysValidJSON(t *testing.T) {
	past := time.Now().Add(-time.Hour).Unix()
	tok := makeJWT(t,
		map[string]any{"alg": "HS256"},
		map[string]any{"sub": "user", "exp": float64(past)})
	stdout, _, code := runSocAllowFail(t, "decode", "jwt", "--expired", "--json", tok)
	if code != 1 {
		t.Errorf("expected exit 1, got %d", code)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("stdout not valid JSON with --expired --json: %v\n%s", err, stdout)
	}
	if _, ok := parsed["header"]; !ok {
		t.Error("JSON output missing 'header'")
	}
	if _, ok := parsed["payload"]; !ok {
		t.Error("JSON output missing 'payload'")
	}
}

func TestJWTClaimOrdering(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()
	tok := makeJWT(t,
		map[string]any{"alg": "HS256"},
		map[string]any{
			"zebra": "z",
			"apple": "a",
			"exp":   float64(future),
			"sub":   "u",
			"iss":   "i",
		})
	out := runSoc(t, "", "decode", "jwt", tok)

	payloadIdx := strings.Index(out, "Payload")
	if payloadIdx < 0 {
		t.Fatalf("no 'Payload' section in output:\n%s", out)
	}
	body := out[payloadIdx:]

	expected := []string{"iss:", "sub:", "exp:", "apple:", "zebra:"}
	last := -1
	for _, key := range expected {
		idx := strings.Index(body, key)
		if idx < 0 {
			t.Errorf("claim %q not found in payload section", key)
			continue
		}
		if idx < last {
			t.Errorf("claim %q appears out of order (expected order: %v)\nbody:\n%s", key, expected, body)
		}
		last = idx
	}
}

func TestJWTTimestampFormatting(t *testing.T) {
	tok := makeJWT(t,
		map[string]any{"alg": "HS256"},
		map[string]any{"sub": "u", "exp": float64(1704067200)})
	out := runSoc(t, "", "decode", "jwt", tok)
	if !strings.Contains(out, "exp: 1704067200 (") {
		t.Errorf("expected 'exp: 1704067200 (...' in output; got:\n%s", out)
	}
}

func TestJWTWholeNumberNotScientific(t *testing.T) {
	// A large whole-number custom claim must not render in scientific notation.
	tok := makeJWT(t,
		map[string]any{"alg": "HS256"},
		map[string]any{"sub": "u", "userId": float64(1234567890)})
	out := runSoc(t, "", "decode", "jwt", tok)
	if !strings.Contains(out, "userId: 1234567890") {
		t.Errorf("expected 'userId: 1234567890' in output; got:\n%s", out)
	}
	if strings.Contains(out, "1.23456789e") {
		t.Errorf("output contains scientific notation; got:\n%s", out)
	}
}

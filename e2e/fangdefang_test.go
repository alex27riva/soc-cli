/*
Copyright © 2026 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package e2e_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var (
	binPath    string
	configPath string
)

func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "soc-cli-e2e-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpDir)

	binPath = filepath.Join(tmpDir, "soc")
	configPath = filepath.Join(tmpDir, "config.yaml")

	if err := os.WriteFile(configPath, []byte("api_keys: {}\n"), 0o644); err != nil {
		panic(err)
	}

	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	repoRoot := filepath.Dir(wd)

	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = repoRoot
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic(err)
	}

	os.Exit(m.Run())
}

func runSoc(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	full := append([]string{"--config", configPath}, args...)
	cmd := exec.Command(binPath, full...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("soc %v failed: %v\nstderr: %s", full, err, stderr.String())
	}
	return strings.TrimRight(stdout.String(), "\n")
}

func TestDefangFangRoundtrip(t *testing.T) {
	inputs := []string{
		"http://example.com",
		"https://malicious.example.com/path?q=1",
		"https://sub.domain.example.co.uk",
		"user@example.com",
		"admin@mail.company.io",
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			defanged := runSoc(t, "", "defang", in)
			fanged := runSoc(t, "", "fang", defanged)
			if fanged != in {
				t.Errorf("roundtrip: %q -> %q -> %q", in, defanged, fanged)
			}
		})
	}
}

func TestDefangOutput(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"http url", "http://example.com", "hxxp://example[.]com"},
		{"https url with path", "https://example.com/path", "hxxps://example[.]com/path"},
		{"email", "user@example.com", "user[at]example[.]com"},
		{"subdomain email", "alice@mail.example.co.uk", "alice[at]mail[.]example[.]co[.]uk"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := runSoc(t, "", "defang", tc.in)
			if got != tc.want {
				t.Errorf("defang %q = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestFangOutput(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"defanged http", "hxxp://example[.]com", "http://example.com"},
		{"defanged https", "hxxps://example[.]com/path", "https://example.com/path"},
		{"defanged email", "user[at]example[.]com", "user@example.com"},
		{"at in parens", "user(at)example[.]com", "user@example.com"},
		{"at in brackets", "user[@]example[.]com", "user@example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := runSoc(t, "", "fang", tc.in)
			if got != tc.want {
				t.Errorf("fang %q = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestDefangIdempotent(t *testing.T) {
	inputs := []string{
		"http://example.com",
		"https://a.b.c/path",
		"user@example.com",
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			once := runSoc(t, "", "defang", in)
			twice := runSoc(t, "", "defang", once)
			if once != twice {
				t.Errorf("not idempotent: defang(%q)=%q, defang^2=%q", in, once, twice)
			}
		})
	}
}

func TestFangIdempotent(t *testing.T) {
	inputs := []string{
		"hxxp://example[.]com",
		"user[at]example[.]com",
		"http://example.com",
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			once := runSoc(t, "", "fang", in)
			twice := runSoc(t, "", "fang", once)
			if once != twice {
				t.Errorf("not idempotent: fang(%q)=%q, fang^2=%q", in, once, twice)
			}
		})
	}
}

func TestDefangStdin(t *testing.T) {
	viaArg := runSoc(t, "", "defang", "http://example.com")
	viaStdin := runSoc(t, "http://example.com\n", "defang")
	if viaArg != viaStdin {
		t.Errorf("stdin vs arg mismatch: stdin=%q arg=%q", viaStdin, viaArg)
	}
}

func TestFangStdin(t *testing.T) {
	viaArg := runSoc(t, "", "fang", "hxxp://example[.]com")
	viaStdin := runSoc(t, "hxxp://example[.]com\n", "fang")
	if viaArg != viaStdin {
		t.Errorf("stdin vs arg mismatch: stdin=%q arg=%q", viaStdin, viaArg)
	}
}

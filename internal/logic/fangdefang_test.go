/*
Copyright © 2026 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package logic

import "testing"

func TestDefang(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{"http url", "http://example.com", "hxxp://example[.]com"},
		{"https url", "https://example.com", "hxxps://example[.]com"},
		{"https with path", "https://example.com/a/b?q=1", "hxxps://example[.]com/a/b?q=1"},
		{"email", "user@example.com", "user[at]example[.]com"},
		{"multi-level email", "alice@mail.example.co.uk", "alice[at]mail[.]example[.]co[.]uk"},
		{"bare domain", "example.com", "example[.]com"},
		{"already defanged url", "hxxp://example[.]com", "hxxp://example[.]com"},
		{"already defanged email", "user[at]example[.]com", "user[at]example[.]com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Defang(tc.input); got != tc.want {
				t.Errorf("Defang(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestDefangEmail(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{"simple", "user@example.com", "user[at]example[.]com"},
		{"subdomain", "a@b.c.d", "a[at]b[.]c[.]d"},
		{"dots in local part", "first.last@example.com", "first[.]last[at]example[.]com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := DefangEmail(tc.input); got != tc.want {
				t.Errorf("DefangEmail(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestDefangURL(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{"http", "http://example.com", "hxxp://example[.]com"},
		{"https", "https://example.com", "hxxps://example[.]com"},
		{"https with path", "https://example.com/foo/bar", "hxxps://example[.]com/foo/bar"},
		{"no scheme", "example.com", "example[.]com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := DefangURL(tc.input); got != tc.want {
				t.Errorf("DefangURL(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestFang(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{"defanged http", "hxxp://example[.]com", "http://example.com"},
		{"defanged https", "hxxps://example[.]com/path", "https://example.com/path"},
		{"defanged email", "user[at]example[.]com", "user@example.com"},
		{"at in parens", "user(at)example[.]com", "user@example.com"},
		{"at in brackets", "user[@]example[.]com", "user@example.com"},
		{"already fanged", "http://example.com", "http://example.com"},
		{"plain text", "no iocs here", "no iocs here"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Fang(tc.input); got != tc.want {
				t.Errorf("Fang(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestFangDefangRoundtrip(t *testing.T) {
	inputs := []string{
		"http://example.com",
		"https://malicious.example.com/path?q=1",
		"https://sub.domain.example.co.uk",
		"user@example.com",
		"admin@mail.company.io",
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			if got := Fang(Defang(in)); got != in {
				t.Errorf("roundtrip: %q -> %q -> %q", in, Defang(in), got)
			}
		})
	}
}

func TestDefangIdempotent(t *testing.T) {
	inputs := []string{
		"http://example.com",
		"https://a.b.c/path",
		"user@example.com",
		"alice@mail.example.co.uk",
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			once := Defang(in)
			twice := Defang(once)
			if once != twice {
				t.Errorf("not idempotent: Defang(%q)=%q, Defang^2=%q", in, once, twice)
			}
		})
	}
}

func TestFangIdempotent(t *testing.T) {
	inputs := []string{
		"hxxp://example[.]com",
		"hxxps://example[.]com/path",
		"user[at]example[.]com",
		"http://example.com",
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			once := Fang(in)
			twice := Fang(once)
			if once != twice {
				t.Errorf("not idempotent: Fang(%q)=%q, Fang^2=%q", in, once, twice)
			}
		})
	}
}

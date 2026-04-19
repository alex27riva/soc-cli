/*
Copyright © 2026 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package logic

import "testing"

func TestBase64Encode(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{"empty", "", ""},
		{"ascii", "hello", "aGVsbG8="},
		{"with spaces", "hello world", "aGVsbG8gd29ybGQ="},
		{"unicode", "ciao 🌍", "Y2lhbyDwn4yN"},
		{"newline", "line\n", "bGluZQo="},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Base64Encode(tc.input); got != tc.want {
				t.Errorf("Base64Encode(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestBase64Decode(t *testing.T) {
	tests := []struct {
		name, input, want string
		wantErr           bool
	}{
		{"empty", "", "", false},
		{"ascii", "aGVsbG8=", "hello", false},
		{"with spaces", "aGVsbG8gd29ybGQ=", "hello world", false},
		{"unicode", "Y2lhbyDwn4yN", "ciao 🌍", false},
		{"invalid", "not_base64!", "", true},
		{"bad padding", "aGVsbG8", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Base64Decode(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Base64Decode(%q) err = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("Base64Decode(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestBase64RoundTrip(t *testing.T) {
	inputs := []string{"", "hello", "hello world", "ciao 🌍", "a\nb\tc", "!@#$%^&*()"}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			got, err := Base64Decode(Base64Encode(in))
			if err != nil {
				t.Fatalf("roundtrip err: %v", err)
			}
			if got != in {
				t.Errorf("roundtrip: got %q, want %q", got, in)
			}
		})
	}
}

func TestURLEncode(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{"empty", "", ""},
		{"plain", "hello", "hello"},
		{"space", "hello world", "hello%20world"},
		{"special", "a/b?c=d&e=f", "a%2Fb%3Fc%3Dd%26e%3Df"},
		{"literal plus", "a+b", "a%2Bb"},
		{"unicode", "ciao 🌍", "ciao%20%F0%9F%8C%8D"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := URLEncode(tc.input); got != tc.want {
				t.Errorf("URLEncode(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestURLDecode(t *testing.T) {
	tests := []struct {
		name, input, want string
		wantErr           bool
	}{
		{"empty", "", "", false},
		{"plain", "hello", "hello", false},
		{"percent space", "hello%20world", "hello world", false},
		{"plus as space", "hello+world", "hello world", false},
		{"special", "a%2Fb%3Fc%3Dd", "a/b?c=d", false},
		{"unicode", "ciao%20%F0%9F%8C%8D", "ciao 🌍", false},
		{"invalid", "%ZZ", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := URLDecode(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("URLDecode(%q) err = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("URLDecode(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestURLRoundTrip(t *testing.T) {
	inputs := []string{"", "hello", "hello world", "a/b?c=d", "a+b", "ciao 🌍"}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			got, err := URLDecode(URLEncode(in))
			if err != nil {
				t.Fatalf("roundtrip err: %v", err)
			}
			if got != in {
				t.Errorf("roundtrip: got %q, want %q", got, in)
			}
		})
	}
}

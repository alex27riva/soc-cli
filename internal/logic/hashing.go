/*
Copyright © 2024 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package logic

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"os"
)

type HashAlgorithm struct {
	Name string
	New  func() hash.Hash
}

// HashAlgorithms lists the algorithms computed by HashFile, in output order.
// Register a new algorithm by appending to this slice.
var HashAlgorithms = []HashAlgorithm{
	{Name: "MD5", New: md5.New},
	{Name: "SHA1", New: sha1.New},
	{Name: "SHA256", New: sha256.New},
}

type HashResult struct {
	Name string
	Hex  string
}

// HashFile opens path and returns the hex digest of every registered
// algorithm, computed in a single read pass.
func HashFile(path string) ([]HashResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return HashReader(f)
}

// HashReader computes the hex digest of every registered algorithm for the
// contents of r in a single read pass.
func HashReader(r io.Reader) ([]HashResult, error) {
	hashers := make([]hash.Hash, len(HashAlgorithms))
	writers := make([]io.Writer, len(HashAlgorithms))
	for i, a := range HashAlgorithms {
		h := a.New()
		hashers[i] = h
		writers[i] = h
	}

	if _, err := io.Copy(io.MultiWriter(writers...), r); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	results := make([]HashResult, len(HashAlgorithms))
	for i, a := range HashAlgorithms {
		results[i] = HashResult{Name: a.Name, Hex: fmt.Sprintf("%x", hashers[i].Sum(nil))}
	}
	return results, nil
}

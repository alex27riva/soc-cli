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
	"sync"

	"lukechampine.com/blake3"
)

type HashAlgorithm struct {
	Name       string
	New        func() hash.Hash
	Deprecated bool // set for broken algorithms (MD5, SHA1) — off by default at the CLI
}

// HashAlgorithms lists the algorithms computed by HashFile, in output order.
// Register a new algorithm by appending to this slice.
var HashAlgorithms = []HashAlgorithm{
	{Name: "MD5", New: md5.New, Deprecated: true},
	{Name: "SHA1", New: sha1.New, Deprecated: true},
	{Name: "SHA256", New: sha256.New},
	{Name: "BLAKE3", New: func() hash.Hash { return blake3.New(32, nil) }},
}

type HashResult struct {
	Name string
	Hex  string
}

// HashFile opens path and hashes it with every registered algorithm.
func HashFile(path string) ([]HashResult, error) {
	return HashFileWith(path, HashAlgorithms)
}

// HashFileWith opens path and hashes it with the given algorithms only.
func HashFileWith(path string, algos []HashAlgorithm) ([]HashResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return HashReaderWith(f, algos)
}

// HashReader computes the hex digest of every registered algorithm for the
// contents of r.
func HashReader(r io.Reader) ([]HashResult, error) {
	return HashReaderWith(r, HashAlgorithms)
}

// HashReaderWith computes the hex digest of each given algorithm for r.
// Each algorithm runs in its own goroutine so large inputs are hashed in
// parallel across CPU cores.
func HashReaderWith(r io.Reader, algos []HashAlgorithm) ([]HashResult, error) {
	const chunkSize = 64 * 1024

	hashers := make([]hash.Hash, len(algos))
	chans := make([]chan []byte, len(algos))
	var wg sync.WaitGroup

	for i, a := range algos {
		hashers[i] = a.New()
		chans[i] = make(chan []byte, 8)
		h, ch := hashers[i], chans[i]
		wg.Go(func() {
			for buf := range ch {
				h.Write(buf)
			}
		})
	}

	var readErr error
	for {
		buf := make([]byte, chunkSize)
		n, err := r.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			for _, ch := range chans {
				ch <- chunk
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			readErr = err
			break
		}
	}

	for _, ch := range chans {
		close(ch)
	}
	wg.Wait()

	if readErr != nil {
		return nil, fmt.Errorf("read: %w", readErr)
	}

	results := make([]HashResult, len(algos))
	for i, a := range algos {
		results[i] = HashResult{Name: a.Name, Hex: fmt.Sprintf("%x", hashers[i].Sum(nil))}
	}
	return results, nil
}

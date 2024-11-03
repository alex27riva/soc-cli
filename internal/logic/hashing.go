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
	"io"
	"log"
	"os"
)

func ComputeMd5(file *os.File) string {
	hmd5 := md5.New()
	if _, err := io.Copy(hmd5, file); err != nil {
		log.Fatal("failed to calculate MD5 of file: %w", err)
	}
	hashmd5 := hmd5.Sum(nil)
	hexmd5 := fmt.Sprintf("%x", hashmd5)
	return hexmd5
}

func ComputeSha1(file *os.File) string {
	h1 := sha1.New()
	if _, err := io.Copy(h1, file); err != nil {
		log.Fatal("failed to calculate SHA1 of file: %w", err)
	}
	hashsha1 := h1.Sum(nil)
	hex1 := fmt.Sprintf("%x", hashsha1)
	return hex1
}

func ComputeSha256(file *os.File) string {
	h256 := sha256.New()
	if _, err := io.Copy(h256, file); err != nil {
		log.Fatal("failed to calculate SHA256 of file: %w", err)
	}
	hash256 := h256.Sum(nil)
	hex256 := fmt.Sprintf("%x", hash256)
	return hex256
}

package main

import (
	"crypto/sha512"
	"encoding/hex"
)

// SHA512HashEncode SHA512 hash a string
func SHA512HashEncode(s string) string {
	hasher := sha512.New()
	hasher.Write([]byte(s))
	return hex.EncodeToString(hasher.Sum(nil))
}

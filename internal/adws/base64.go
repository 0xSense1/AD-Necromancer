//go:build windows

package adws

import "encoding/base64"

// b64Encode encodes bytes to a standard base64 string.
func b64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// b64Decode decodes a standard base64 string to bytes.
func b64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

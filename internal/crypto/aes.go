package crypto

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// EncryptedZip holds an in-memory AES-256-GCM encrypted zip archive and its key.
type EncryptedZip struct {
	Data []byte // encrypted zip bytes (AES-256-GCM ciphertext)
	Key  []byte // 32-byte AES key (print or save separately)
	IV   []byte // 12-byte GCM nonce, prepended to Data
}

// BuildEncryptedZip takes a map of filename→content, creates a zip archive in memory,
// then AES-256-GCM encrypts the entire zip buffer.
func BuildEncryptedZip(files map[string][]byte) (*EncryptedZip, error) {
	// Step 1: Build zip in memory
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			return nil, fmt.Errorf("zip create %s: %w", name, err)
		}
		if _, err := w.Write(content); err != nil {
			return nil, fmt.Errorf("zip write %s: %w", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("zip close: %w", err)
	}

	// Step 2: Generate random AES-256 key
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("key gen: %w", err)
	}

	// Step 3: AES-256-GCM encrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm init: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce gen: %w", err)
	}

	// Seal: nonce || ciphertext+tag
	ciphertext := gcm.Seal(nonce, nonce, zipBuf.Bytes(), nil)

	return &EncryptedZip{
		Data: ciphertext,
		Key:  key,
		IV:   nonce,
	}, nil
}

// Decrypt decrypts an EncryptedZip back to raw zip bytes (for verification/testing).
func Decrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}

// KeyHex returns the AES key as a hex string (for display/saving).
func (e *EncryptedZip) KeyHex() string {
	return hex.EncodeToString(e.Key)
}

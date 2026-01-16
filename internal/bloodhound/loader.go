package bloodhound

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// Loader handles ingesting BloodHound JSON files
type Loader struct {
	Data BloodHoundData
}

func NewLoader() *Loader {
	return &Loader{
		Data: BloodHoundData{},
	}
}

// LoadFromDirectory reads all BloodHound JSON files from a directory
func (l *Loader) LoadFromDirectory(dirPath string) error {
	files, err := ioutil.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	for _, f := range files {
		if filepath.Ext(f.Name()) == ".json" {
			fullPath := filepath.Join(dirPath, f.Name())
			if err := l.loadFile(fullPath); err != nil {
				// Continue loading other files even if one fails
				continue
			}
		}
	}
	return nil
}

func (l *Loader) loadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	bytes, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	// Wrapper to handle the "data" root key often found in BH exports
	type BHWrapper struct {
		Data []Node      `json:"data"`
		Meta interface{} `json:"meta"`
	}

	var wrapper BHWrapper
	if err := json.Unmarshal(bytes, &wrapper); err != nil {
		// Fallback if structure is different
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Skip if no data
	if len(wrapper.Data) == 0 {
		return nil
	}

	fname := strings.ToLower(filepath.Base(path))

	// Use case-insensitive substring matching
	switch {
	case strings.Contains(fname, "enterpriseca"):
		l.Data.EnterpriseCAs = append(l.Data.EnterpriseCAs, wrapper.Data...)
	case strings.Contains(fname, "certtemplate"):
		l.Data.CertTemplates = append(l.Data.CertTemplates, wrapper.Data...)
	case strings.Contains(fname, "user"):
		l.Data.Users = append(l.Data.Users, wrapper.Data...)
	case strings.Contains(fname, "group"):
		l.Data.Groups = append(l.Data.Groups, wrapper.Data...)
	case strings.Contains(fname, "computer"):
		l.Data.Computers = append(l.Data.Computers, wrapper.Data...)
	case strings.Contains(fname, "domain"):
		l.Data.Domains = append(l.Data.Domains, wrapper.Data...)
	case strings.Contains(fname, "gpo"):
		l.Data.GPOs = append(l.Data.GPOs, wrapper.Data...)
	case strings.Contains(fname, "ou"):
		l.Data.OUs = append(l.Data.OUs, wrapper.Data...)
	case strings.Contains(fname, "container"):
		l.Data.Containers = append(l.Data.Containers, wrapper.Data...)
	}

	return nil
}

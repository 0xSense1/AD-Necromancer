//go:build windows

package collector

import (
	"fmt"

	"ad-necromancer/internal/adws"
	"ad-necromancer/internal/bh"
	"ad-necromancer/internal/ldap"
)

// Method controls which collection protocol to use.
type Method string

const (
	MethodAuto Method = "auto"
	MethodADWS Method = "adws"
	MethodLDAP Method = "ldap"
)

// Config holds all parameters needed for collection.
type Config struct {
	Domain   string
	DC       string
	Username string
	Password string
	Method   Method
	Stealth  bool
}

// Collect runs the appropriate collector based on config and returns populated ADData.
func Collect(cfg Config) (*bh.ADData, error) {
	switch cfg.Method {
	case MethodADWS:
		return collectADWS(cfg)
	case MethodLDAP:
		return collectLDAP(cfg)
	default: // auto: try ADWS first, fall back to LDAP
		return collectAuto(cfg)
	}
}

func collectAuto(cfg Config) (*bh.ADData, error) {
	if !cfg.Stealth {
		fmt.Println("[*] Auto-detect: probing ADWS (port 9389)...")
	}
	adwsClient, err := adws.NewClient(cfg.Domain, cfg.DC, cfg.Username, cfg.Password, cfg.Stealth)
	if err == nil && adwsClient.Probe() {
		if !cfg.Stealth {
			fmt.Println("[+] ADWS reachable — using ADWS collection (stealthier protocol)")
		}
		return collectADWS(cfg)
	}

	if !cfg.Stealth {
		fmt.Println("[*] ADWS unavailable — falling back to LDAP")
	}
	return collectLDAP(cfg)
}

func collectADWS(cfg Config) (*bh.ADData, error) {
	client, err := adws.NewClient(cfg.Domain, cfg.DC, cfg.Username, cfg.Password, cfg.Stealth)
	if err != nil {
		return nil, fmt.Errorf("ADWS init: %w", err)
	}
	return client.CollectAll()
}

func collectLDAP(cfg Config) (*bh.ADData, error) {
	client, err := ldap.NewClient(cfg.Domain, cfg.DC, cfg.Username, cfg.Password)
	if err != nil {
		return nil, fmt.Errorf("LDAP init: %w", err)
	}
	defer client.Close()
	c := ldap.NewCollector(client, cfg.Stealth)
	return c.CollectAll()
}

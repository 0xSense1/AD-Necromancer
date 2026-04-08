//go:build windows

package ldap

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

// Client wraps a go-ldap connection with our credential + server info.
type Client struct {
	conn   *goldap.Conn
	Domain string
	DC     string
	User   string
	Pass   string
}

// NewClient creates and authenticates an LDAP connection.
// Tries LDAPS (636) first, falls back to plain LDAP (389).
func NewClient(domain, dc, user, pass string) (*Client, error) {
	if dc == "" {
		// Auto-discover DC via DNS SRV record
		var err error
		dc, err = discoverDC(domain)
		if err != nil {
			return nil, fmt.Errorf("DC discovery failed: %w", err)
		}
	}

	conn, err := dialLDAP(dc)
	if err != nil {
		return nil, fmt.Errorf("LDAP connect failed: %w", err)
	}

	// Bind with credentials
	bindUser := fmt.Sprintf("%s@%s", user, domain)
	if err := conn.Bind(bindUser, pass); err != nil {
		conn.Close()
		return nil, fmt.Errorf("LDAP bind failed: %w", err)
	}

	return &Client{
		conn:   conn,
		Domain: domain,
		DC:     dc,
		User:   user,
		Pass:   pass,
	}, nil
}

// Close terminates the LDAP connection.
func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// dialLDAP tries LDAPS on 636, then plain LDAP on 389.
func dialLDAP(dc string) (*goldap.Conn, error) {
	// Try LDAPS first
	tlsCfg := &tls.Config{InsecureSkipVerify: true} // In red team context; real certs vary
	conn, err := goldap.DialTLS("tcp", fmt.Sprintf("%s:636", dc), tlsCfg)
	if err == nil {
		conn.SetTimeout(30 * time.Second)
		return conn, nil
	}

	// Fall back to plain LDAP
	conn, err = goldap.Dial("tcp", fmt.Sprintf("%s:389", dc))
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(30 * time.Second)
	return conn, nil
}

// discoverDC looks up the domain controller via DNS SRV record.
func discoverDC(domain string) (string, error) {
	_, addrs, err := net.LookupSRV("ldap", "tcp", domain)
	if err != nil || len(addrs) == 0 {
		// Fallback: just use the domain name (often resolves to DC)
		return domain, nil
	}
	target := addrs[0].Target
	// Trim trailing dot
	if len(target) > 0 && target[len(target)-1] == '.' {
		target = target[:len(target)-1]
	}
	return target, nil
}

// BaseDN constructs the base distinguished name from a domain FQDN.
// e.g. "corp.local" → "DC=corp,DC=local"
func BaseDN(domain string) string {
	dn := ""
	parts := splitDomain(domain)
	for i, p := range parts {
		if i > 0 {
			dn += ","
		}
		dn += "DC=" + p
	}
	return dn
}

func splitDomain(domain string) []string {
	var parts []string
	cur := ""
	for _, r := range domain {
		if r == '.' {
			if cur != "" {
				parts = append(parts, cur)
				cur = ""
			}
		} else {
			cur += string(r)
		}
	}
	if cur != "" {
		parts = append(parts, cur)
	}
	return parts
}

// Search executes an LDAP search and returns entries.
func (c *Client) Search(baseDN, filter string, attrs []string) ([]*goldap.Entry, error) {
	req := goldap.NewSearchRequest(
		baseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0,     // size limit (0 = unlimited)
		0,     // time limit
		false, // types only
		filter,
		attrs,
		nil,
	)

	result, err := c.conn.SearchWithPaging(req, 500)
	if err != nil {
		return nil, err
	}
	return result.Entries, nil
}

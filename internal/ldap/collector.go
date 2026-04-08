//go:build windows

package ldap

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"ad-necromancer/internal/bh"
	goldap "github.com/go-ldap/ldap/v3"
)

// Collector uses the LDAP client to collect all AD objects.
type Collector struct {
	client  *Client
	baseDN  string
	jitter  bool // add random delay between collection batches (stealth mode)
}

// NewCollector creates a new Collector.
func NewCollector(client *Client, stealth bool) *Collector {
	return &Collector{
		client: client,
		baseDN: BaseDN(client.Domain),
		jitter: stealth,
	}
}

// CollectAll runs all collection methods and returns a populated ADData struct.
func (c *Collector) CollectAll() (*bh.ADData, error) {
	data := &bh.ADData{}
	var err error

	steps := []struct {
		name string
		fn   func() error
	}{
		{"users", func() error {
			data.Users, err = c.CollectUsers()
			return err
		}},
		{"groups", func() error {
			data.Groups, err = c.CollectGroups()
			return err
		}},
		{"computers", func() error {
			data.Computers, err = c.CollectComputers()
			return err
		}},
		{"domains", func() error {
			data.Domains, err = c.CollectDomains()
			return err
		}},
		{"gpos", func() error {
			data.GPOs, err = c.CollectGPOs()
			return err
		}},
		{"ous", func() error {
			data.OUs, err = c.CollectOUs()
			return err
		}},
		{"certtemplates", func() error {
			data.CertTemplates, err = c.CollectCertTemplates()
			return err
		}},
		{"enterprisecas", func() error {
			data.EnterpriseCAs, err = c.CollectEnterpriseCAs()
			return err
		}},
	}

	for _, step := range steps {
		if err := step.fn(); err != nil {
			// Non-fatal: log and continue to next object type
			fmt.Printf("[!] LDAP collect %s: %v\n", step.name, err)
		}
		if c.jitter {
			delay := jitterDelay(200, 800)
			time.Sleep(delay)
		}
	}

	return data, nil
}

// CollectUsers pulls all user objects with relevant attributes.
func (c *Collector) CollectUsers() ([]bh.Node, error) {
	attrs := []string{
		"objectSid", "sAMAccountName", "userPrincipalName", "distinguishedName",
		"name", "description", "adminCount", "userAccountControl",
		"pwdLastSet", "lastLogon", "lastLogonTimestamp", "whenCreated",
		"servicePrincipalName", "memberOf", "nTSecurityDescriptor",
		"msDS-AllowedToActOnBehalfOfOtherIdentity",
		"msDS-KeyCredentialLink", "userPassword", "unixUserPassword",
	}
	entries, err := c.client.Search(c.baseDN,
		"(&(objectCategory=person)(objectClass=user))", attrs)
	if err != nil {
		return nil, err
	}
	return entriesToNodes(entries, "User"), nil
}

// CollectGroups pulls all group objects.
func (c *Collector) CollectGroups() ([]bh.Node, error) {
	attrs := []string{
		"objectSid", "sAMAccountName", "distinguishedName", "name",
		"description", "adminCount", "member", "memberOf",
		"nTSecurityDescriptor", "groupType",
	}
	entries, err := c.client.Search(c.baseDN, "(objectClass=group)", attrs)
	if err != nil {
		return nil, err
	}
	return entriesToNodes(entries, "Group"), nil
}

// CollectComputers pulls all computer objects.
func (c *Collector) CollectComputers() ([]bh.Node, error) {
	attrs := []string{
		"objectSid", "sAMAccountName", "dNSHostName", "distinguishedName",
		"name", "description", "adminCount", "operatingSystem",
		"operatingSystemVersion", "userAccountControl", "lastLogon",
		"nTSecurityDescriptor", "msDS-AllowedToActOnBehalfOfOtherIdentity",
		"msDS-AllowedToDelegateTo", "msLAPS-Password", "ms-MCS-AdmPwd",
	}
	entries, err := c.client.Search(c.baseDN, "(objectClass=computer)", attrs)
	if err != nil {
		return nil, err
	}
	return entriesToNodes(entries, "Computer"), nil
}

// CollectDomains pulls the root domain object.
func (c *Collector) CollectDomains() ([]bh.Node, error) {
	attrs := []string{
		"objectSid", "distinguishedName", "name", "description",
		"nTSecurityDescriptor", "msDS-Behavior-Version", "objectGUID",
	}
	entries, err := c.client.Search(c.baseDN,
		"(objectClass=domain)", attrs)
	if err != nil {
		return nil, err
	}
	return entriesToNodes(entries, "Domain"), nil
}

// CollectGPOs pulls all Group Policy Objects.
func (c *Collector) CollectGPOs() ([]bh.Node, error) {
	attrs := []string{
		"objectGUID", "displayName", "distinguishedName", "name",
		"description", "gPCFileSysPath", "nTSecurityDescriptor",
	}
	entries, err := c.client.Search(c.baseDN,
		"(objectClass=groupPolicyContainer)", attrs)
	if err != nil {
		return nil, err
	}
	return entriesToNodes(entries, "GPO"), nil
}

// CollectOUs pulls all Organizational Units.
func (c *Collector) CollectOUs() ([]bh.Node, error) {
	attrs := []string{
		"objectGUID", "ou", "distinguishedName", "name",
		"description", "nTSecurityDescriptor", "gpLink",
	}
	entries, err := c.client.Search(c.baseDN,
		"(objectClass=organizationalUnit)", attrs)
	if err != nil {
		return nil, err
	}
	return entriesToNodes(entries, "OU"), nil
}

// CollectCertTemplates pulls ADCS certificate templates.
func (c *Collector) CollectCertTemplates() ([]bh.Node, error) {
	configDN := "CN=Configuration," + c.baseDN
	attrs := []string{
		"objectGUID", "cn", "distinguishedName", "name",
		"msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
		"msPKI-RA-Signature", "pKIExtendedKeyUsage",
		"msPKI-Certificate-Application-Policy", "nTSecurityDescriptor",
		"msPKI-Template-Schema-Version",
	}
	entries, err := c.client.Search(configDN,
		"(objectClass=pKICertificateTemplate)", attrs)
	if err != nil {
		return nil, err
	}
	return entriesToNodes(entries, "CertTemplate"), nil
}

// CollectEnterpriseCAs pulls Enterprise CA objects.
func (c *Collector) CollectEnterpriseCAs() ([]bh.Node, error) {
	configDN := "CN=Configuration," + c.baseDN
	attrs := []string{
		"objectGUID", "cn", "distinguishedName", "name",
		"cACertificate", "nTSecurityDescriptor",
		"certificateTemplates",
	}
	entries, err := c.client.Search(configDN,
		"(objectClass=certificationAuthority)", attrs)
	if err != nil {
		return nil, err
	}
	return entriesToNodes(entries, "EnterpriseCA"), nil
}

// ---- Helpers ----

// entriesToNodes converts raw LDAP entries into bh.Node objects.
func entriesToNodes(entries []*goldap.Entry, objType string) []bh.Node {
	nodes := make([]bh.Node, 0, len(entries))
	for _, e := range entries {
		node := bh.Node{
			ObjectIdentifier: getSID(e),
			Properties:       entryToProperties(e),
			ObjectType:       objType,
		}
		node.Properties.RawAttributes = entryToRawMap(e)
		nodes = append(nodes, node)
	}
	return nodes
}

// getSID extracts and formats the object's SID from the objectSid attribute.
func getSID(e *goldap.Entry) string {
	raw := e.GetRawAttributeValue("objectSid")
	if len(raw) == 0 {
		// Fallback to objectGUID
		guid := e.GetRawAttributeValue("objectGUID")
		if len(guid) > 0 {
			return strings.ToUpper(hex.EncodeToString(guid))
		}
		return e.DN
	}
	return decodeSID(raw)
}

// decodeSID converts a raw binary SID to the S-X-X-... string format.
func decodeSID(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	revision := b[0]
	subAuthCount := int(b[1])
	// Authority: bytes 2-7, big-endian 48-bit
	authority := int64(0)
	for i := 2; i < 8; i++ {
		authority = (authority << 8) | int64(b[i])
	}
	sid := fmt.Sprintf("S-%d-%d", revision, authority)
	for i := 0; i < subAuthCount; i++ {
		if 8+i*4+4 > len(b) {
			break
		}
		sub := uint32(b[8+i*4]) |
			uint32(b[9+i*4])<<8 |
			uint32(b[10+i*4])<<16 |
			uint32(b[11+i*4])<<24
		sid += fmt.Sprintf("-%d", sub)
	}
	return sid
}

// entryToProperties maps common LDAP attributes into the bh.Properties struct.
func entryToProperties(e *goldap.Entry) bh.Properties {
	uac := parseUint64(e.GetAttributeValue("userAccountControl"))
	return bh.Properties{
		Name:              e.GetAttributeValue("name"),
		Domain:            dnToDomain(e.DN),
		Description:       e.GetAttributeValue("description"),
		DistinguishedName: e.DN,
		HighValue:         false, // Determined by BH graph at import time
		AdminCount:        e.GetAttributeValue("adminCount") == "1",
		Enabled:           uac == 0 || (uac&0x2 == 0),
		PasswordLastSet:   parseWindowsTime(e.GetAttributeValue("pwdLastSet")),
		LastLogon:         parseWindowsTime(e.GetAttributeValue("lastLogon")),
		OperatingSystem:   e.GetAttributeValue("operatingSystem"),
		SAMAccountName:    e.GetAttributeValue("sAMAccountName"),
		ServicePrincipalNames: e.GetAttributeValues("servicePrincipalName"),
		Members:           e.GetAttributeValues("member"),
		MemberOf:          e.GetAttributeValues("memberOf"),
	}
}

// entryToRawMap captures all raw attribute values for forensic completeness.
func entryToRawMap(e *goldap.Entry) map[string][]string {
	m := make(map[string][]string, len(e.Attributes))
	for _, a := range e.Attributes {
		m[a.Name] = a.Values
	}
	return m
}

// dnToDomain converts a distinguished name to a domain FQDN.
// e.g. "CN=foo,DC=corp,DC=local" → "corp.local"
func dnToDomain(dn string) string {
	var parts []string
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "DC=") {
			parts = append(parts, part[3:])
		}
	}
	return strings.Join(parts, ".")
}

func parseUint64(s string) uint64 {
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

// parseWindowsTime converts a Windows FILETIME (100ns intervals since 1601-01-01) to Unix timestamp.
func parseWindowsTime(s string) int64 {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v == 0 || v == 9223372036854775807 {
		return -1
	}
	// Convert to Unix: subtract 116444736000000000 (offset 1601→1970) then divide by 10M
	unix := (v - 116444736000000000) / 10000000
	return unix
}

// jitterDelay returns a random duration between minMs and maxMs milliseconds.
func jitterDelay(minMs, maxMs int) time.Duration {
	// Simple LCG-based quick random to avoid importing math/rand
	tick := time.Now().UnixNano()
	spread := int64(maxMs - minMs)
	ms := minMs + int(tick%spread)
	return time.Duration(ms) * time.Millisecond
}

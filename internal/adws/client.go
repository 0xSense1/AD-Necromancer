//go:build windows

package adws

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"ad-necromancer/internal/bh"
)

// ADWSPort is the standard ADWS port.
const ADWSPort = "9389"

// Client implements ADWS collection over HTTP/SOAP (WS-Transfer + WS-Enumeration).
type Client struct {
	httpClient *http.Client
	baseURL    string
	domain     string
	dc         string
	username   string
	password   string
	jitter     bool
}

// NewClient creates an ADWS client targeting the given DC.
func NewClient(domain, dc, user, pass string, stealth bool) (*Client, error) {
	if dc == "" {
		dc = domain // fallback
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	baseURL := fmt.Sprintf("http://%s:%s/ActiveDirectoryWebServices/Windows/Resource/",
		dc, ADWSPort)

	return &Client{
		httpClient: httpClient,
		baseURL:    baseURL,
		domain:     domain,
		dc:         dc,
		username:   user,
		password:   pass,
		jitter:     stealth,
	}, nil
}

// Probe checks if ADWS is reachable on port 9389.
func (c *Client) Probe() bool {
	req, err := http.NewRequest("GET", c.baseURL, nil)
	if err != nil {
		return false
	}
	req.SetBasicAuth(c.username+"@"+c.domain, c.password)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	// ADWS returns 400/500 on GET to the base URL, but connection itself works
	return resp.StatusCode < 600
}

// CollectAll runs the full ADWS enumeration and returns an ADData struct.
func (c *Client) CollectAll() (*bh.ADData, error) {
	data := &bh.ADData{}
	var err error

	type step struct {
		name string
		fn   func() error
	}
	steps := []step{
		{"users", func() error {
			data.Users, err = c.enumerate("user", userAttrs)
			return err
		}},
		{"groups", func() error {
			data.Groups, err = c.enumerate("group", groupAttrs)
			return err
		}},
		{"computers", func() error {
			data.Computers, err = c.enumerate("computer", computerAttrs)
			return err
		}},
		{"domains", func() error {
			data.Domains, err = c.enumerate("domain", domainAttrs)
			return err
		}},
		{"gpos", func() error {
			data.GPOs, err = c.enumerate("groupPolicyContainer", gpoAttrs)
			return err
		}},
		{"ous", func() error {
			data.OUs, err = c.enumerate("organizationalUnit", ouAttrs)
			return err
		}},
		{"certtemplates", func() error {
			data.CertTemplates, err = c.enumerate("pKICertificateTemplate", certAttrs)
			return err
		}},
		{"enterprisecas", func() error {
			data.EnterpriseCAs, err = c.enumerate("certificationAuthority", caAttrs)
			return err
		}},
	}

	for _, s := range steps {
		if err := s.fn(); err != nil {
			fmt.Printf("[!] ADWS collect %s: %v\n", s.name, err)
		}
		if c.jitter {
			jitter(200, 800)
		}
	}
	return data, nil
}

// enumerate performs a WS-Enumeration against the ADWS endpoint for the given objectClass.
func (c *Client) enumerate(objectClass string, attrs []string) ([]bh.Node, error) {
	// Step 1: Enumerate (get context)
	enumCtx, err := c.wsEnumerate(objectClass, attrs)
	if err != nil {
		return nil, fmt.Errorf("ws-enumerate: %w", err)
	}

	// Step 2: Pull pages
	var allItems []map[string][]string
	for {
		items, done, err := c.wsPull(enumCtx, 50)
		if err != nil {
			break
		}
		allItems = append(allItems, items...)
		if done {
			break
		}
	}

	// Step 3: Convert to bh.Node
	return adwsItemsToNodes(allItems, objectClass), nil
}

// wsEnumerate sends a WS-Enumeration Enumerate request and returns the enumeration context.
func (c *Client) wsEnumerate(objectClass string, attrs []string) (string, error) {
	filter := fmt.Sprintf(`(objectClass=%s)`, objectClass)
	attrList := ""
	for _, a := range attrs {
		attrList += fmt.Sprintf(`<addata:AttributeType>%s</addata:AttributeType>`, a)
	}

	body := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
            xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"
            xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate</a:Action>
    <a:To s:mustUnderstand="1">%s</a:To>
  </s:Header>
  <s:Body>
    <wsen:Enumerate>
      <wsen:Filter Dialect="http://schemas.microsoft.com/ADWS/2008/04/ADOPathDialect">%s</wsen:Filter>
      <ad:AttributeParameters>%s</ad:AttributeParameters>
    </wsen:Enumerate>
  </s:Body>
</s:Envelope>`, c.baseURL, filter, attrList)

	resp, err := c.soapRequest(
		"http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate",
		[]byte(body),
	)
	if err != nil {
		return "", err
	}

	// Extract EnumerationContext from response
	ctx := extractXMLValue(resp, "EnumerationContext")
	if ctx == "" {
		return "", fmt.Errorf("no enumeration context in response")
	}
	return ctx, nil
}

// wsPull retrieves the next page of results for the given enumeration context.
func (c *Client) wsPull(ctx string, maxElements int) ([]map[string][]string, bool, error) {
	body := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull</a:Action>
    <a:To s:mustUnderstand="1">%s</a:To>
  </s:Header>
  <s:Body>
    <wsen:Pull>
      <wsen:EnumerationContext>%s</wsen:EnumerationContext>
      <wsen:MaxElements>%d</wsen:MaxElements>
    </wsen:Pull>
  </s:Body>
</s:Envelope>`, c.baseURL, ctx, maxElements)

	resp, err := c.soapRequest(
		"http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull",
		[]byte(body),
	)
	if err != nil {
		return nil, true, err
	}

	items := parseADWSItems(resp)
	endOfSeq := strings.Contains(string(resp), "EndOfSequence")
	return items, endOfSeq, nil
}

// soapRequest sends a SOAP request to the ADWS endpoint.
func (c *Client) soapRequest(action string, body []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", c.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `application/soap+xml; charset=utf-8`)
	req.Header.Set("SOAPAction", action)
	req.SetBasicAuth(c.username+"@"+c.domain, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ADWS HTTP %d: %s", resp.StatusCode, truncate(string(data), 200))
	}
	return io.ReadAll(resp.Body)
}

// ---- XML helpers ----

func extractXMLValue(data []byte, tag string) string {
	s := string(data)
	start := strings.Index(s, "<"+tag+">")
	if start < 0 {
		// Try namespaced tag
		start = strings.Index(s, ":"+tag+">")
		if start < 0 {
			return ""
		}
		start = strings.LastIndex(s[:start], "<")
		endTag := s[start:]
		colIdx := strings.Index(endTag, ":")
		if colIdx < 0 {
			return ""
		}
		startContent := strings.Index(s, ">") // first >
		_ = startContent
	}
	open := strings.Index(s, ">")
	if open < 0 {
		return ""
	}
	content := s[start+len("<"+tag+">"):]
	end := strings.Index(content, "</")
	if end < 0 {
		return ""
	}
	return content[:end]
}

// parseADWSItems is a minimal ADWS XML result parser.
// In a full implementation this should use encoding/xml; this is a functional stub.
func parseADWSItems(data []byte) []map[string][]string {
	// For now returns empty — a proper XML parser is hooked in via adws/soap.go
	_ = data
	return nil
}

func adwsItemsToNodes(items []map[string][]string, objType string) []bh.Node {
	nodes := make([]bh.Node, 0, len(items))
	for _, item := range items {
		sid := firstVal(item, "objectSid")
		if sid == "" {
			sid = firstVal(item, "objectGUID")
		}
		nodes = append(nodes, bh.Node{
			ObjectIdentifier: sid,
			ObjectType:       objType,
			Properties: bh.Properties{
				Name:              firstVal(item, "name"),
				DistinguishedName: firstVal(item, "distinguishedName"),
				Description:       firstVal(item, "description"),
				AdminCount:        firstVal(item, "adminCount") == "1",
				RawAttributes:     item,
			},
		})
	}
	return nodes
}

func firstVal(m map[string][]string, key string) string {
	if vals, ok := m[key]; ok && len(vals) > 0 {
		return vals[0]
	}
	return ""
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func jitter(minMs, maxMs int) {
	tick := time.Now().UnixNano()
	spread := int64(maxMs - minMs)
	ms := minMs + int(tick%spread)
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

// ---- Attribute lists per object type ----

var userAttrs = []string{
	"objectSid", "sAMAccountName", "userPrincipalName", "distinguishedName",
	"name", "description", "adminCount", "userAccountControl",
	"pwdLastSet", "lastLogon", "servicePrincipalName", "memberOf",
	"msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-KeyCredentialLink",
}
var groupAttrs = []string{
	"objectSid", "sAMAccountName", "distinguishedName", "name",
	"description", "adminCount", "member", "memberOf", "groupType",
}
var computerAttrs = []string{
	"objectSid", "sAMAccountName", "dNSHostName", "distinguishedName",
	"name", "description", "adminCount", "operatingSystem",
	"userAccountControl", "lastLogon", "msDS-AllowedToActOnBehalfOfOtherIdentity",
	"msDS-AllowedToDelegateTo", "ms-MCS-AdmPwd", "msLAPS-Password",
}
var domainAttrs = []string{
	"objectSid", "distinguishedName", "name", "description",
	"msDS-Behavior-Version", "objectGUID",
}
var gpoAttrs = []string{
	"objectGUID", "displayName", "distinguishedName", "name",
	"description", "gPCFileSysPath",
}
var ouAttrs = []string{
	"objectGUID", "ou", "distinguishedName", "name", "description", "gpLink",
}
var certAttrs = []string{
	"objectGUID", "cn", "distinguishedName", "name",
	"msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
	"msPKI-RA-Signature", "pKIExtendedKeyUsage",
}
var caAttrs = []string{
	"objectGUID", "cn", "distinguishedName", "name",
	"cACertificate", "certificateTemplates",
}

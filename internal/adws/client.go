//go:build windows

// Package adws implements a production-grade Active Directory Web Services (ADWS)
// client using the .NET Message Framing (MC-NMF) protocol over TCP port 9389,
// Negotiate authentication (NTLM), and SOAP/XML-encoded WS-Enumeration requests.
//
// Protocol stack:
//   TCP:9389 → MC-NMF framing → NTLM negotiate → SOAP-XML → WS-Enumeration
package adws

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"ad-necromancer/internal/bh"

	"github.com/Azure/go-ntlmssp"
)

// ADWSPort is the standard ADWS TCP port.
const ADWSPort = "9389"

// maxRetries is the number of connection/request retries before giving up.
const maxRetries = 3

// dialTimeout / requestTimeout govern per-operation deadlines.
const (
	dialTimeout    = 10 * time.Second
	requestTimeout = 60 * time.Second
)

// ── MC-NMF record type bytes ─────────────────────────────────────────────────

const (
	recVersionRequest  byte = 0x00
	recVersionResponse byte = 0x01
	recModeRequest     byte = 0x02
	recModeResponse    byte = 0x03  // unused by client, received from server
	recViaRequest      byte = 0x04
	recKnownEncoding   byte = 0x06
	recUpgradeRequest  byte = 0x09
	recUpgradeResponse byte = 0x0A
	recPreambleAck     byte = 0x0B
	recEndRecord       byte = 0x0C  // end of the preamble handshake
	recUnsizedEnvelope byte = 0x16  // sized envelope follows
	recSizedEnvelope   byte = 0x14
	recFault           byte = 0x11
	recEnd             byte = 0x17

	// MC-NMF encoding IDs
	encodingBinaryInBandDictionary byte = 0x08 // MC-NBFX / MC-NBFSE — but we use text SOAP (0x03)
	encodingUTF8Text               byte = 0x03 // plain XML over NMF, easiest to implement correctly

	// Session mode: singleton
	modeSingleton byte = 0x01
)

// ── Client ───────────────────────────────────────────────────────────────────

// Client is the production ADWS client.
type Client struct {
	domain   string
	dc       string
	username string
	password string
	stealth  bool

	// via is the NMF "Via" URI that identifies the ADWS endpoint.
	viaEnum     string
	viaResource string
}

// NewClient creates an ADWS client without opening a connection yet.
func NewClient(domain, dc, user, pass string, stealth bool) (*Client, error) {
	if dc == "" {
		// Auto-discover: use the domain name directly
		dc = domain
	}
	c := &Client{
		domain:   domain,
		dc:       dc,
		username: user,
		password: pass,
		stealth:  stealth,
	}
	// ADWS exposes two endpoints:
	//   /ActiveDirectoryWebServices/Windows/Enumeration  — WS-Enumeration
	//   /ActiveDirectoryWebServices/Windows/Resource     — WS-Transfer Get
	c.viaEnum = fmt.Sprintf("net.tcp://%s:%s/ActiveDirectoryWebServices/Windows/Enumeration", dc, ADWSPort)
	c.viaResource = fmt.Sprintf("net.tcp://%s:%s/ActiveDirectoryWebServices/Windows/Resource", dc, ADWSPort)
	return c, nil
}

// Probe does a quick TCP connect to port 9389 to check reachability without
// performing any authentication.
func (c *Client) Probe() bool {
	for attempt := 0; attempt < maxRetries; attempt++ {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(c.dc, ADWSPort), dialTimeout)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// CollectAll runs the full ADWS enumeration and returns a populated ADData.
func (c *Client) CollectAll() (*bh.ADData, error) {
	if !c.stealth {
		fmt.Println("[*] ADWS-First: Connecting to port 9389...")
	}

	// Verify reachability before starting expensive operations
	if !c.Probe() {
		if !c.stealth {
			fmt.Println("[!] ADWS-First: Failed - falling back to LDAP Ghosting")
		}
		return nil, fmt.Errorf("ADWS port 9389 not reachable on %s", c.dc)
	}

	if !c.stealth {
		fmt.Println("[+] ADWS-First: Connected successfully")
	}

	data := &bh.ADData{}

	type step struct {
		name      string
		objClass  string
		filter    string
		attrs     []string
		configDN  bool // search under CN=Configuration
		dest      *[]bh.Node
	}

	baseDN := domainToDN(c.domain)
	configDN := "CN=Configuration," + baseDN

	steps := []step{
		{
			name:     "users",
			filter:   "(&(objectCategory=person)(objectClass=user))",
			attrs:    userAttrs,
			dest:     &data.Users,
		},
		{
			name:   "groups",
			filter: "(objectClass=group)",
			attrs:  groupAttrs,
			dest:   &data.Groups,
		},
		{
			name:   "computers",
			filter: "(objectClass=computer)",
			attrs:  computerAttrs,
			dest:   &data.Computers,
		},
		{
			name:   "domains",
			filter: "(objectClass=domain)",
			attrs:  domainAttrs,
			dest:   &data.Domains,
		},
		{
			name:   "gpos",
			filter: "(objectClass=groupPolicyContainer)",
			attrs:  gpoAttrs,
			dest:   &data.GPOs,
		},
		{
			name:   "ous",
			filter: "(objectClass=organizationalUnit)",
			attrs:  ouAttrs,
			dest:   &data.OUs,
		},
		{
			name:     "certtemplates",
			filter:   "(objectClass=pKICertificateTemplate)",
			attrs:    certAttrs,
			configDN: true,
			dest:     &data.CertTemplates,
		},
		{
			name:     "enterprisecas",
			filter:   "(objectClass=certificationAuthority)",
			attrs:    caAttrs,
			configDN: true,
			dest:     &data.EnterpriseCAs,
		},
	}

	for _, s := range steps {
		searchBase := baseDN
		if s.configDN {
			searchBase = configDN
		}

		nodes, err := c.enumerate(searchBase, s.filter, s.attrs)
		if err != nil {
			if !c.stealth {
				fmt.Printf("[!] ADWS collect %s: %v\n", s.name, err)
			}
			// Non-fatal: continue to next object type
		} else {
			*s.dest = nodes
			if !c.stealth {
				fmt.Printf("[+] ADWS collected %d %s\n", len(nodes), s.name)
			}
		}

		if c.stealth {
			jitter(300, 900)
		}
	}

	return data, nil
}

// ── Core enumeration ─────────────────────────────────────────────────────────

// enumerate opens a fresh NMF connection, performs NTLM negotiate, issues a
// WS-Enumeration Enumerate + repeated Pull until EndOfSequence, closes the
// connection, and returns all collected nodes.
func (c *Client) enumerate(baseDN, filter string, attrs []string) ([]bh.Node, error) {
	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		nodes, err := c.enumerateOnce(baseDN, filter, attrs)
		if err == nil {
			return nodes, nil
		}
		lastErr = err
		if !c.stealth {
			fmt.Printf("[~] ADWS retry %d/%d for filter %q: %v\n", attempt, maxRetries, filter, err)
		}
		time.Sleep(time.Duration(attempt*500) * time.Millisecond)
	}
	return nil, lastErr
}

func (c *Client) enumerateOnce(baseDN, filter string, attrs []string) ([]bh.Node, error) {
	// 1. Dial raw TCP
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(c.dc, ADWSPort), dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	// 2. Perform MC-NMF preamble handshake
	if err := nmfPreamble(conn, c.viaEnum); err != nil {
		return nil, fmt.Errorf("NMF preamble: %w", err)
	}

	// 3. NTLM negotiate over the NMF channel
	if err := c.ntlmHandshake(conn); err != nil {
		return nil, fmt.Errorf("NTLM: %w", err)
	}

	// 4. WS-Enumeration: Enumerate → get context handle
	enumCtx, err := c.wsEnumerate(conn, baseDN, filter, attrs)
	if err != nil {
		return nil, fmt.Errorf("ws-enumerate: %w", err)
	}

	// 5. Pull pages until EndOfSequence
	var allItems []map[string][]string
	for {
		_ = conn.SetDeadline(time.Now().Add(requestTimeout))
		items, done, pullErr := c.wsPull(conn, enumCtx, 250)
		if pullErr != nil {
			break
		}
		allItems = append(allItems, items...)
		if done {
			break
		}
	}

	// 6. Convert raw attribute maps → bh.Node
	return adwsItemsToNodes(allItems, c.domain), nil
}

// ── MC-NMF framing ───────────────────────────────────────────────────────────

// nmfPreamble performs the .NET Message Framing connection-mode preamble.
//
//	Client → Server: VersionRequest(1,0) ModeRequest(singleton) ViaRequest(uri)
//	                  KnownEncoding(UTF8Text) PreambleEnd
//	Server → Client: VersionResponse(1,0) PreambleAck
func nmfPreamble(conn net.Conn, via string) error {
	_ = conn.SetDeadline(time.Now().Add(dialTimeout))

	var buf bytes.Buffer

	// VersionRequest: 0x00 Major=1 Minor=0
	buf.WriteByte(recVersionRequest)
	buf.WriteByte(1)
	buf.WriteByte(0)

	// ModeRequest: 0x02 mode=singleton(1)
	buf.WriteByte(recModeRequest)
	buf.WriteByte(modeSingleton)

	// ViaRequest: 0x04 <var-len encoded length> <UTF-8 bytes>
	buf.WriteByte(recViaRequest)
	viaBytes := []byte(via)
	writeVarLen(&buf, len(viaBytes))
	buf.Write(viaBytes)

	// KnownEncoding: 0x06 <encoding-id>
	buf.WriteByte(recKnownEncoding)
	buf.WriteByte(encodingUTF8Text)

	// PreambleEnd: 0x0C
	buf.WriteByte(recEndRecord)

	if _, err := conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("write preamble: %w", err)
	}

	// Read server response — expect VersionResponse + PreambleAck
	// Each is a 1-3 byte record; we read until we get 0x0B (PreambleAck)
	for {
		rec, err := readRecord(conn)
		if err != nil {
			return fmt.Errorf("read preamble response: %w", err)
		}
		switch rec[0] {
		case recVersionResponse:
			// Major/Minor — ignore version check for compatibility
		case recPreambleAck:
			return nil // handshake complete
		case recFault:
			return fmt.Errorf("server fault during preamble: %x", rec)
		}
	}
}

// writeVarLen writes a multi-byte variable-length integer (MC-NMF style).
// Values < 128 are written as a single byte; larger values use 7-bit encoding.
func writeVarLen(w io.Writer, n int) {
	b := make([]byte, 0, 5)
	for {
		chunk := n & 0x7F
		n >>= 7
		if n > 0 {
			chunk |= 0x80
		}
		b = append(b, byte(chunk))
		if n == 0 {
			break
		}
	}
	_, _ = w.Write(b)
}

// readVarLen reads a multi-byte variable-length integer from the connection.
func readVarLen(r io.Reader) (int, error) {
	result := 0
	shift := 0
	for {
		var b [1]byte
		if _, err := r.Read(b[:]); err != nil {
			return 0, err
		}
		result |= (int(b[0]) & 0x7F) << shift
		if b[0]&0x80 == 0 {
			break
		}
		shift += 7
		if shift > 28 {
			return 0, fmt.Errorf("varint overflow")
		}
	}
	return result, nil
}

// readRecord reads one MC-NMF record. For simple single-byte records (Version,
// Mode, PreambleAck, End) it returns just the type byte. For payload records
// (SizedEnvelope) it reads the length-prefixed body.
func readRecord(r io.Reader) ([]byte, error) {
	var typeBuf [1]byte
	if _, err := io.ReadFull(r, typeBuf[:]); err != nil {
		return nil, err
	}
	switch typeBuf[0] {
	case recVersionResponse:
		// 2 more bytes: major, minor
		extra := make([]byte, 2)
		if _, err := io.ReadFull(r, extra); err != nil {
			return nil, err
		}
		return append(typeBuf[:], extra...), nil

	case recModeResponse:
		// 1 more byte: mode
		extra := make([]byte, 1)
		if _, err := io.ReadFull(r, extra); err != nil {
			return nil, err
		}
		return append(typeBuf[:], extra...), nil

	case recPreambleAck, recEndRecord, recEnd:
		return typeBuf[:], nil

	case recFault:
		// fault: var-len string
		n, err := readVarLen(r)
		if err != nil {
			return nil, err
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(r, msg); err != nil {
			return nil, err
		}
		return append(typeBuf[:], msg...), nil

	case recSizedEnvelope:
		// 4-byte little-endian length followed by payload
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return nil, err
		}
		size := binary.LittleEndian.Uint32(lenBuf[:])
		if size > 16*1024*1024 {
			return nil, fmt.Errorf("envelope too large: %d bytes", size)
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
		return payload, nil

	case recUnsizedEnvelope:
		// Chunked: read 4-byte chunk size, chunk data, repeat until 0-length chunk
		var out []byte
		for {
			var lenBuf [4]byte
			if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
				return nil, err
			}
			chunkSize := binary.LittleEndian.Uint32(lenBuf[:])
			if chunkSize == 0 {
				break
			}
			chunk := make([]byte, chunkSize)
			if _, err := io.ReadFull(r, chunk); err != nil {
				return nil, err
			}
			out = append(out, chunk...)
		}
		return out, nil

	default:
		return nil, fmt.Errorf("unknown NMF record type: 0x%02X", typeBuf[0])
	}
}

// sendEnvelope wraps an XML SOAP body in an MC-NMF SizedEnvelope record and
// writes it to the connection.
func sendEnvelope(conn net.Conn, xmlBody []byte) error {
	var buf bytes.Buffer
	buf.WriteByte(recSizedEnvelope)
	lb := make([]byte, 4)
	binary.LittleEndian.PutUint32(lb, uint32(len(xmlBody)))
	buf.Write(lb)
	buf.Write(xmlBody)
	_, err := conn.Write(buf.Bytes())
	return err
}

// recvEnvelope reads one NMF record and returns its payload bytes.
func recvEnvelope(conn net.Conn) ([]byte, error) {
	return readRecord(conn)
}

// ── NTLM handshake ───────────────────────────────────────────────────────────

// ntlmHandshake performs a two-step NTLM Negotiate/Challenge/Authenticate over
// the NMF channel. We embed NTLM binary tokens in SOAP Security headers.
func (c *Client) ntlmHandshake(conn net.Conn) error {
	// Step 1: Build NTLM Negotiate token (Type 1)
	negotiateMsg, err := ntlmssp.NewNegotiateMessage(c.domain, "")
	if err != nil {
		return fmt.Errorf("ntlm negotiate: %w", err)
	}

	// Send SOAP envelope with Negotiate token
	neg64 := b64Encode(negotiateMsg)
	negotiateSOAP := buildSecuritySOAP(neg64, c.viaEnum, actionNegotiate)
	_ = conn.SetDeadline(time.Now().Add(requestTimeout))
	if err := sendEnvelope(conn, negotiateSOAP); err != nil {
		return fmt.Errorf("send negotiate: %w", err)
	}

	// Receive challenge (Type 2)
	challengeXML, err := recvEnvelope(conn)
	if err != nil {
		return fmt.Errorf("recv challenge: %w", err)
	}

	challengeToken, err := extractSecurityToken(challengeXML)
	if err != nil {
		return fmt.Errorf("extract challenge: %w", err)
	}

	// Step 2: Build NTLM Authenticate token (Type 3)
	authenticateMsg, err := ntlmssp.ProcessChallenge(challengeToken, c.username, c.password, true)
	if err != nil {
		return fmt.Errorf("ntlm authenticate: %w", err)
	}

	auth64 := b64Encode(authenticateMsg)
	authenticateSOAP := buildSecuritySOAP(auth64, c.viaEnum, actionAuthenticate)
	_ = conn.SetDeadline(time.Now().Add(requestTimeout))
	if err := sendEnvelope(conn, authenticateSOAP); err != nil {
		return fmt.Errorf("send authenticate: %w", err)
	}

	// Receive auth response — should be a 200-equivalent SOAP envelope
	authResp, err := recvEnvelope(conn)
	if err != nil {
		return fmt.Errorf("recv auth response: %w", err)
	}

	// Check for fault
	if bytes.Contains(authResp, []byte("Fault")) || bytes.Contains(authResp, []byte("fault")) {
		return fmt.Errorf("auth rejected by server: %s", truncate(string(authResp), 300))
	}

	return nil
}

// ── WS-Enumeration ───────────────────────────────────────────────────────────

const (
	actionEnumerate    = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
	actionPull         = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull"
	actionNegotiate    = "http://schemas.microsoft.com/ws/2006/05/security/NegotiateLegs/Leg1"
	actionAuthenticate = "http://schemas.microsoft.com/ws/2006/05/security/NegotiateLegs/Leg2"

	nsSOAP  = "http://www.w3.org/2003/05/soap-envelope"
	nsWSA   = "http://www.w3.org/2005/08/addressing"
	nsWSEN  = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"
	nsAD    = "http://schemas.microsoft.com/2008/1/ActiveDirectory"
	nsADDAT = "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"
)

// msgCounter generates unique WS-Addressing MessageID values per session.
// WS-Addressing requires each request to carry a unique MessageID — reusing
// the same ID across paginated Pull requests can trigger server-side
// deduplication, returning only the first page repeatedly.
var msgCounter uint64

func nextMsgID() string {
	n := atomic.AddUint64(&msgCounter, 1)
	return fmt.Sprintf("urn:uuid:necromancer-%d-%d", time.Now().UnixNano(), n)
}

// wsEnumerate sends Enumerate and returns the EnumerationContext handle.
func (c *Client) wsEnumerate(conn net.Conn, baseDN, filter string, attrs []string) (string, error) {
	attrXML := buildAttrList(attrs)

	body := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="%s"
            xmlns:a="%s"
            xmlns:wsen="%s"
            xmlns:ad="%s"
            xmlns:addata="%s">
  <s:Header>
    <a:Action s:mustUnderstand="1">%s</a:Action>
    <a:To s:mustUnderstand="1">%s</a:To>
    <a:MessageID>%s</a:MessageID>
  </s:Header>
  <s:Body>
    <wsen:Enumerate>
      <wsen:Filter Dialect="http://schemas.microsoft.com/ADWS/2008/04/ADOPathDialect">%s</wsen:Filter>
      <ad:AttributeParameters>%s</ad:AttributeParameters>
      <ad:BaseObjectSearchProperties>
        <ad:SearchBase>%s</ad:SearchBase>
        <ad:SearchScope>subtree</ad:SearchScope>
      </ad:BaseObjectSearchProperties>
    </wsen:Enumerate>
  </s:Body>
</s:Envelope>`,
		nsSOAP, nsWSA, nsWSEN, nsAD, nsADDAT,
		actionEnumerate,
		c.viaEnum,
		nextMsgID(),
		xmlEscape(filter),
		attrXML,
		xmlEscape(baseDN),
	)

	_ = conn.SetDeadline(time.Now().Add(requestTimeout))
	if err := sendEnvelope(conn, []byte(body)); err != nil {
		return "", err
	}

	resp, err := recvEnvelope(conn)
	if err != nil {
		return "", err
	}

	ctx := extractXMLValue(resp, "EnumerationContext")
	if ctx == "" {
		return "", fmt.Errorf("server response missing EnumerationContext: %s", truncate(string(resp), 400))
	}
	return ctx, nil
}

// wsPull issues one Pull request and returns items + EndOfSequence flag.
func (c *Client) wsPull(conn net.Conn, enumCtx string, maxElements int) ([]map[string][]string, bool, error) {
	body := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="%s"
            xmlns:a="%s"
            xmlns:wsen="%s">
  <s:Header>
    <a:Action s:mustUnderstand="1">%s</a:Action>
    <a:To s:mustUnderstand="1">%s</a:To>
    <a:MessageID>%s</a:MessageID>
  </s:Header>
  <s:Body>
    <wsen:Pull>
      <wsen:EnumerationContext>%s</wsen:EnumerationContext>
      <wsen:MaxElements>%d</wsen:MaxElements>
    </wsen:Pull>
  </s:Body>
</s:Envelope>`,
		nsSOAP, nsWSA, nsWSEN,
		actionPull,
		c.viaEnum,
		nextMsgID(),
		xmlEscape(enumCtx),
		maxElements,
	)

	if err := sendEnvelope(conn, []byte(body)); err != nil {
		return nil, true, err
	}

	resp, err := recvEnvelope(conn)
	if err != nil {
		return nil, true, err
	}

	items := parseADWSItems(resp)
	endOfSeq := bytes.Contains(resp, []byte("EndOfSequence"))
	return items, endOfSeq, nil
}

// ── XML helpers ──────────────────────────────────────────────────────────────

// adwsItem is used for XML unmarshalling of ADWS Pull responses.
type adwsItem struct {
	XMLName xml.Name
	Attrs   []adwsAttr `xml:",any"`
}

type adwsAttr struct {
	XMLName xml.Name
	Values  []string `xml:",chardata"`
}

// parseADWSItems parses a SOAP Pull response and extracts a slice of attribute maps.
// Each map entry is attrName → []values.
func parseADWSItems(data []byte) []map[string][]string {
	// We look for the Items element and parse each child as an AD object.
	// The response looks like:
	//   <wsen:PullResponse>
	//     <wsen:Items>
	//       <addata:user>
	//         <addata:name><addata:value>...</addata:value></addata:name>
	//         ...
	//       </addata:user>
	//     </wsen:Items>
	//   </wsen:PullResponse>

	type adValue struct {
		Text string `xml:",chardata"`
	}
	type adAttrWrapper struct {
		XMLName xml.Name
		Values  []adValue `xml:"value"`
		// also handle direct text (non-multi-valued)
		Text string `xml:",chardata"`
	}
	type adObject struct {
		XMLName xml.Name
		Attrs   []adAttrWrapper `xml:",any"`
	}
	type itemsBlock struct {
		Objects []adObject `xml:",any"`
	}
	type pullResp struct {
		Items itemsBlock `xml:"Body>PullResponse>Items"`
	}

	var resp pullResp
	if err := xml.Unmarshal(data, &resp); err != nil {
		// Fallback: attempt raw string extraction
		return parseADWSItemsFallback(data)
	}

	var result []map[string][]string
	for _, obj := range resp.Items.Objects {
		m := make(map[string][]string, len(obj.Attrs))
		for _, attr := range obj.Attrs {
			name := localName(attr.XMLName.Local)
			var vals []string
			if len(attr.Values) > 0 {
				for _, v := range attr.Values {
					if v.Text != "" {
						vals = append(vals, v.Text)
					}
				}
			}
			if len(vals) == 0 && strings.TrimSpace(attr.Text) != "" {
				vals = []string{strings.TrimSpace(attr.Text)}
			}
			if len(vals) > 0 {
				m[name] = vals
			}
		}
		if len(m) > 0 {
			result = append(result, m)
		}
	}
	return result
}

// parseADWSItemsFallback does a minimal string-scan fallback when xml.Unmarshal fails.
func parseADWSItemsFallback(data []byte) []map[string][]string {
	// Very simple: find <addata:*> blocks and extract tag/value pairs
	s := string(data)
	var results []map[string][]string

	// Split on common object-type wrappers
	objTypes := []string{"user", "group", "computer", "domain",
		"groupPolicyContainer", "organizationalUnit",
		"pKICertificateTemplate", "certificationAuthority",
		"domainDNS", "trustedDomain"}

	for _, ot := range objTypes {
		openTag := "<addata:" + ot + ">"
		closeTag := "</addata:" + ot + ">"
		start := 0
		for {
			s1 := strings.Index(s[start:], openTag)
			if s1 < 0 {
				break
			}
			s1 += start
			s2 := strings.Index(s[s1:], closeTag)
			if s2 < 0 {
				break
			}
			s2 += s1 + len(closeTag)
			block := s[s1+len(openTag) : s2-len(closeTag)]
			m := extractAttrMap(block)
			if len(m) > 0 {
				results = append(results, m)
			}
			start = s2
		}
	}
	return results
}

// extractAttrMap scans an XML block for <addata:NAME><addata:value>VAL</addata:value></addata:NAME> patterns.
func extractAttrMap(block string) map[string][]string {
	m := make(map[string][]string)
	i := 0
	for i < len(block) {
		// Find next <addata:XXX>
		openIdx := strings.Index(block[i:], "<addata:")
		if openIdx < 0 {
			break
		}
		openIdx += i
		closeAngle := strings.Index(block[openIdx:], ">")
		if closeAngle < 0 {
			break
		}
		closeAngle += openIdx
		tagName := block[openIdx+len("<addata:") : closeAngle]
		// Skip self-closing or attribute tags
		if strings.HasSuffix(tagName, "/") || strings.ContainsAny(tagName, " \t") {
			i = closeAngle + 1
			continue
		}
		closeTag := "</addata:" + tagName + ">"
		endIdx := strings.Index(block[closeAngle:], closeTag)
		if endIdx < 0 {
			i = closeAngle + 1
			continue
		}
		endIdx += closeAngle
		inner := block[closeAngle+1 : endIdx]

		// Extract <addata:value> children
		var vals []string
		vi := 0
		for vi < len(inner) {
			vs := strings.Index(inner[vi:], "<addata:value>")
			if vs < 0 {
				break
			}
			vs += vi
			ve := strings.Index(inner[vs:], "</addata:value>")
			if ve < 0 {
				break
			}
			ve += vs
			val := inner[vs+len("<addata:value>") : ve]
			if val != "" {
				vals = append(vals, val)
			}
			vi = ve + len("</addata:value>")
		}
		// If no <addata:value> children, use direct text content
		if len(vals) == 0 {
			t := stripXMLTags(inner)
			if t != "" {
				vals = []string{t}
			}
		}
		if len(vals) > 0 {
			m[tagName] = vals
		}
		i = endIdx + len(closeTag)
	}
	return m
}

// stripXMLTags removes all XML tags from a string, leaving only text content.
func stripXMLTags(s string) string {
	var out strings.Builder
	inTag := false
	for _, c := range s {
		switch {
		case c == '<':
			inTag = true
		case c == '>':
			inTag = false
		case !inTag:
			out.WriteRune(c)
		}
	}
	return strings.TrimSpace(out.String())
}

// extractXMLValue extracts the text content of the first element matching a
// local tag name (namespace-agnostic).
func extractXMLValue(data []byte, tagLocal string) string {
	s := string(data)
	// Try plain <tag>
	patterns := []string{
		"<" + tagLocal + ">",
		":" + tagLocal + ">",
	}
	for _, pat := range patterns {
		idx := strings.Index(s, pat)
		if idx < 0 {
			continue
		}
		start := idx + len(pat)
		end := strings.Index(s[start:], "<")
		if end < 0 {
			continue
		}
		val := strings.TrimSpace(s[start : start+end])
		if val != "" {
			return val
		}
	}
	return ""
}

// extractSecurityToken pulls a base64-encoded NTLM token from a SOAP Security header.
func extractSecurityToken(data []byte) ([]byte, error) {
	s := string(data)
	// Look for BinarySecurityToken element content
	patterns := []string{"<wsse:BinarySecurityToken", "<BinarySecurityToken"}
	for _, pat := range patterns {
		idx := strings.Index(s, pat)
		if idx < 0 {
			continue
		}
		// Skip to end of opening tag
		end := strings.Index(s[idx:], ">")
		if end < 0 {
			continue
		}
		start := idx + end + 1
		endIdx := strings.Index(s[start:], "<")
		if endIdx < 0 {
			continue
		}
		token64 := strings.TrimSpace(s[start : start+endIdx])
		if token64 != "" {
			return b64Decode(token64)
		}
	}
	return nil, fmt.Errorf("no BinarySecurityToken found in response")
}

// buildSecuritySOAP creates a minimal SOAP envelope carrying an NTLM Negotiate token.
// Each call generates a unique WS-Addressing MessageID to satisfy strict deduplication
// checks on some Windows DCs (reusing the same ID across Negotiate/Authenticate legs
// can cause the Authenticate to be rejected as a replay).
func buildSecuritySOAP(tokenB64, to, action string) []byte {
	const wsseNS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	const wsuNS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	const ntlmType = "http://schemas.microsoft.com/ws/2006/05/security/Negotiate"

	body := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="%s" xmlns:a="%s">
  <s:Header>
    <a:Action s:mustUnderstand="1">%s</a:Action>
    <a:To s:mustUnderstand="1">%s</a:To>
    <a:MessageID>%s</a:MessageID>
    <wsse:Security xmlns:wsse="%s" xmlns:wsu="%s" s:mustUnderstand="1">
      <wsse:BinarySecurityToken
        ValueType="%s"
        EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
        wsu:Id="SecurityToken-1">%s</wsse:BinarySecurityToken>
    </wsse:Security>
  </s:Header>
  <s:Body/>
</s:Envelope>`,
		nsSOAP, nsWSA,
		xmlEscape(action),
		xmlEscape(to),
		nextMsgID(),
		wsseNS, wsuNS,
		ntlmType,
		tokenB64,
	)
	return []byte(body)
}

// buildAttrList returns the <addata:AttributeType> XML block for an attr list.
func buildAttrList(attrs []string) string {
	var sb strings.Builder
	for _, a := range attrs {
		sb.WriteString(fmt.Sprintf("<addata:AttributeType>%s</addata:AttributeType>", a))
	}
	return sb.String()
}

// localName strips any namespace prefix from an XML local name.
func localName(s string) string {
	if idx := strings.LastIndex(s, ":"); idx >= 0 {
		return s[idx+1:]
	}
	return s
}

// xmlEscape escapes a string for safe XML embedding.
func xmlEscape(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

// ── Node conversion ──────────────────────────────────────────────────────────

// adwsItemsToNodes converts raw ADWS attribute maps into bh.Node objects.
// ADWS returns objectSid as a base64-encoded binary blob; we decode it and
// convert to the Windows S-1-5-21-... string format for BloodHound compatibility.
func adwsItemsToNodes(items []map[string][]string, domain string) []bh.Node {
	nodes := make([]bh.Node, 0, len(items))
	for _, item := range items {
		// objectSid from ADWS is base64(binary SID) — must decode + format
		sid := adwsDecodeSID(firstVal(item, "objectSid"))
		if sid == "" {
			// Fallback to objectGUID (also base64 from ADWS)
			guidRaw := firstVal(item, "objectGUID")
			if guidRaw != "" {
				if b, err := base64.StdEncoding.DecodeString(guidRaw); err == nil {
					sid = strings.ToUpper(hex.EncodeToString(b))
				} else {
					sid = guidRaw
				}
			}
		}
		if sid == "" {
			sid = firstVal(item, "distinguishedName")
		}

		uacStr := firstVal(item, "userAccountControl")
		uac := parseUint64(uacStr)
		enabled := uac == 0 || (uac&0x2 == 0)

		spns := item["servicePrincipalName"]

		node := bh.Node{
			ObjectIdentifier: sid,
			Properties: bh.Properties{
				Name:                  firstVal(item, "name"),
				Domain:                domain,
				Description:           firstVal(item, "description"),
				DistinguishedName:     firstVal(item, "distinguishedName"),
				AdminCount:            firstVal(item, "adminCount") == "1",
				Enabled:               enabled,
				PasswordLastSet:       parseWindowsTime(firstVal(item, "pwdLastSet")),
				LastLogon:             parseWindowsTime(firstVal(item, "lastLogon")),
				OperatingSystem:       firstVal(item, "operatingSystem"),
				SAMAccountName:        firstVal(item, "sAMAccountName"),
				ServicePrincipalNames: spns,
				HasSPN:                len(spns) > 0,
				Members:               item["member"],
				MemberOf:              item["memberOf"],
				RawAttributes:         item,
			},
		}
		nodes = append(nodes, node)
	}
	return nodes
}

// adwsDecodeSID decodes a base64-encoded Windows binary SID (as returned by ADWS XML)
// and converts it to the standard S-R-X-Y-... string format.
func adwsDecodeSID(b64 string) string {
	if b64 == "" {
		return ""
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		// Try URL-safe base64 variant
		b, err = base64.URLEncoding.DecodeString(b64)
		if err != nil {
			return ""
		}
	}
	// Binary SID layout: revision(1) subAuthCount(1) authority(6) subAuthorities(4 each)
	if len(b) < 8 {
		return ""
	}
	revision := b[0]
	subAuthCount := int(b[1])
	var authority int64
	for i := 2; i < 8; i++ {
		authority = (authority << 8) | int64(b[i])
	}
	sid := fmt.Sprintf("S-%d-%d", revision, authority)
	for i := 0; i < subAuthCount; i++ {
		if 8+i*4+4 > len(b) {
			break
		}
		sub := binary.LittleEndian.Uint32(b[8+i*4:])
		sid += fmt.Sprintf("-%d", sub)
	}
	return sid
}

// ── Misc helpers ─────────────────────────────────────────────────────────────

// domainToDN converts a domain FQDN to an LDAP DN.
// e.g. "corp.local" → "DC=corp,DC=local"
func domainToDN(domain string) string {
	parts := strings.Split(domain, ".")
	dcs := make([]string, len(parts))
	for i, p := range parts {
		dcs[i] = "DC=" + p
	}
	return strings.Join(dcs, ",")
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
	ms := minMs + rand.Intn(maxMs-minMs)
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

func parseUint64(s string) uint64 {
	if s == "" {
		return 0
	}
	var v uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		v = v*10 + uint64(c-'0')
	}
	return v
}

func parseWindowsTime(s string) int64 {
	v := int64(parseUint64(s))
	if v == 0 || v == 9223372036854775807 {
		return -1
	}
	return (v - 116444736000000000) / 10000000
}

// ── Attribute lists ──────────────────────────────────────────────────────────

var userAttrs = []string{
	"objectSid", "sAMAccountName", "userPrincipalName", "distinguishedName",
	"name", "description", "adminCount", "userAccountControl",
	"pwdLastSet", "lastLogon", "lastLogonTimestamp",
	"servicePrincipalName", "memberOf",
	"nTSecurityDescriptor",
	"msDS-AllowedToActOnBehalfOfOtherIdentity",
	"msDS-KeyCredentialLink",
}

var groupAttrs = []string{
	"objectSid", "sAMAccountName", "distinguishedName", "name",
	"description", "adminCount", "member", "memberOf", "groupType",
	"nTSecurityDescriptor",
}

var computerAttrs = []string{
	"objectSid", "sAMAccountName", "dNSHostName", "distinguishedName",
	"name", "description", "adminCount", "operatingSystem",
	"operatingSystemVersion", "userAccountControl", "lastLogon",
	"nTSecurityDescriptor",
	"msDS-AllowedToActOnBehalfOfOtherIdentity",
	"msDS-AllowedToDelegateTo",
	"msLAPS-Password", "ms-MCS-AdmPwd",
}

var domainAttrs = []string{
	"objectSid", "distinguishedName", "name", "description",
	"msDS-Behavior-Version", "objectGUID", "nTSecurityDescriptor",
}

var gpoAttrs = []string{
	"objectGUID", "displayName", "distinguishedName", "name",
	"description", "gPCFileSysPath", "nTSecurityDescriptor",
}

var ouAttrs = []string{
	"objectGUID", "ou", "distinguishedName", "name",
	"description", "gpLink", "nTSecurityDescriptor",
}

var certAttrs = []string{
	"objectGUID", "cn", "distinguishedName", "name",
	"msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
	"msPKI-RA-Signature", "pKIExtendedKeyUsage",
	"msPKI-Certificate-Application-Policy",
	"msPKI-Template-Schema-Version",
	"nTSecurityDescriptor",
}

var caAttrs = []string{
	"objectGUID", "cn", "distinguishedName", "name",
	"cACertificate", "certificateTemplates",
	"nTSecurityDescriptor",
}

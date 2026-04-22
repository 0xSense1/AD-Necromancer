package bh

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Formatter converts collected ADData into BloodHound CE v6 JSON files.
type Formatter struct {
	data *ADData
}

// NewFormatter creates a new Formatter for the given ADData.
func NewFormatter(data *ADData) *Formatter {
	return &Formatter{data: data}
}

// FormatAll returns a map of filename → JSON bytes for all BH CE v6 output files.
func (f *Formatter) FormatAll() (map[string][]byte, error) {
	files := make(map[string][]byte)
	var err error

	type step struct {
		name string
		fn   func() ([]byte, error)
	}
	steps := []step{
		{"users.json", f.formatUsers},
		{"groups.json", f.formatGroups},
		{"computers.json", f.formatComputers},
		{"domains.json", f.formatDomains},
		{"gpos.json", f.formatGPOs},
		{"ous.json", f.formatOUs},
		{"certtemplates.json", f.formatCertTemplates},
		{"enterprisecas.json", f.formatEnterpriseCAs},
	}

	for _, s := range steps {
		files[s.name], err = s.fn()
		if err != nil {
			return nil, fmt.Errorf("format %s: %w", s.name, err)
		}
	}
	return files, nil
}

func (f *Formatter) formatUsers() ([]byte, error) {
	entries := make([]UserEntry, 0, len(f.data.Users))
	for _, n := range f.data.Users {
		entries = append(entries, nodeToUserEntry(n))
	}
	out := UserFile{
		Data: entries,
		Meta: FileMeta{Methods: 3, Type: "users", Count: len(entries), Version: 6},
	}
	return json.MarshalIndent(out, "", "  ")
}

func (f *Formatter) formatGroups() ([]byte, error) {
	entries := make([]GroupEntry, 0, len(f.data.Groups))
	for _, n := range f.data.Groups {
		entries = append(entries, nodeToGroupEntry(n))
	}
	out := GroupFile{
		Data: entries,
		Meta: FileMeta{Methods: 3, Type: "groups", Count: len(entries), Version: 6},
	}
	return json.MarshalIndent(out, "", "  ")
}

func (f *Formatter) formatComputers() ([]byte, error) {
	entries := make([]ComputerEntry, 0, len(f.data.Computers))
	for _, n := range f.data.Computers {
		entries = append(entries, nodeToComputerEntry(n))
	}
	out := ComputerFile{
		Data: entries,
		Meta: FileMeta{Methods: 3, Type: "computers", Count: len(entries), Version: 6},
	}
	return json.MarshalIndent(out, "", "  ")
}

func (f *Formatter) formatDomains() ([]byte, error) {
	entries := make([]DomainEntry, 0, len(f.data.Domains))
	for _, n := range f.data.Domains {
		entries = append(entries, nodeToDomainEntry(n))
	}
	out := DomainFile{
		Data: entries,
		Meta: FileMeta{Methods: 3, Type: "domains", Count: len(entries), Version: 6},
	}
	return json.MarshalIndent(out, "", "  ")
}

func (f *Formatter) formatGPOs() ([]byte, error) {
	entries := make([]GPOEntry, 0, len(f.data.GPOs))
	for _, n := range f.data.GPOs {
		entries = append(entries, GPOEntry{
			ObjectIdentifier: n.ObjectIdentifier,
			Aces:             n.Aces,
			IsACLProtected:   n.IsACLProtected,
			Properties:       n.Properties,
		})
	}
	out := GPOFile{
		Data: entries,
		Meta: FileMeta{Methods: 3, Type: "gpos", Count: len(entries), Version: 6},
	}
	return json.MarshalIndent(out, "", "  ")
}

func (f *Formatter) formatOUs() ([]byte, error) {
	entries := make([]OUEntry, 0, len(f.data.OUs))
	for _, n := range f.data.OUs {
		entries = append(entries, OUEntry{
			ObjectIdentifier: n.ObjectIdentifier,
			ChildObjects:     []TypedPrincipal{},
			Links:            []GPOLink{},
			Aces:             n.Aces,
			IsACLProtected:   n.IsACLProtected,
			Properties:       n.Properties,
		})
	}
	out := OUFile{
		Data: entries,
		Meta: FileMeta{Methods: 3, Type: "ous", Count: len(entries), Version: 6},
	}
	return json.MarshalIndent(out, "", "  ")
}

func (f *Formatter) formatCertTemplates() ([]byte, error) {
	entries := make([]CertTemplateEntry, 0, len(f.data.CertTemplates))
	for _, n := range f.data.CertTemplates {
		entries = append(entries, CertTemplateEntry{
			ObjectIdentifier: n.ObjectIdentifier,
			Aces:             n.Aces,
			IsACLProtected:   n.IsACLProtected,
			Properties:       enrichCertTemplateProperties(n),
		})
	}
	out := CertTemplateFile{
		Data: entries,
		Meta: FileMeta{Methods: 3, Type: "certtemplates", Count: len(entries), Version: 6},
	}
	return json.MarshalIndent(out, "", "  ")
}

func (f *Formatter) formatEnterpriseCAs() ([]byte, error) {
	entries := make([]EnterpriseCAEntry, 0, len(f.data.EnterpriseCAs))
	for _, n := range f.data.EnterpriseCAs {
		entries = append(entries, EnterpriseCAEntry{
			ObjectIdentifier:     n.ObjectIdentifier,
			EnabledCertTemplates: []TypedPrincipal{},
			Aces:                 n.Aces,
			IsACLProtected:       n.IsACLProtected,
			Properties:           n.Properties,
		})
	}
	out := EnterpriseCAFile{
		Data: entries,
		Meta: FileMeta{Methods: 3, Type: "enterprisecas", Count: len(entries), Version: 6},
	}
	return json.MarshalIndent(out, "", "  ")
}

// ---- Node → Typed Entry converters ----

func nodeToUserEntry(n Node) UserEntry {
	props := n.Properties
	if len(props.ServicePrincipalNames) > 0 {
		props.HasSPN = true
	}
	// UAC flag 4194304 = DontRequirePreauth (AS-REP Roasting)
	rawUAC := props.RawAttributes["userAccountControl"]
	if len(rawUAC) > 0 {
		uac := parseInt64(rawUAC[0])
		props.DontReqPreAuth = (uac & 4194304) != 0
		props.UnconstrainedDelegation = (uac & 524288) != 0
	}
	return UserEntry{
		ObjectIdentifier:  n.ObjectIdentifier,
		AllowedToDelegate: []TypedPrincipal{},
		HasSIDHistory:     []TypedPrincipal{},
		SPNTargets:        parseSPNTargets(props.ServicePrincipalNames),
		Aces:              n.Aces,
		IsACLProtected:    n.IsACLProtected,
		Properties:        props,
	}
}

func nodeToGroupEntry(n Node) GroupEntry {
	members := make([]TypedPrincipal, 0)
	for _, dn := range n.Properties.Members {
		members = append(members, TypedPrincipal{
			ObjectIdentifier: dn, // BH resolves DN to SID at import
			ObjectType:       "Unknown",
		})
	}
	return GroupEntry{
		ObjectIdentifier: n.ObjectIdentifier,
		Members:          members,
		Aces:             n.Aces,
		IsACLProtected:   n.IsACLProtected,
		Properties:       n.Properties,
	}
}

func nodeToComputerEntry(n Node) ComputerEntry {
	props := n.Properties
	// Check LAPS
	raw := props.RawAttributes
	if v, ok := raw["ms-MCS-AdmPwd"]; ok && len(v) > 0 && v[0] != "" {
		props.HasLAPS = true
	}
	if v, ok := raw["msLAPS-Password"]; ok && len(v) > 0 && v[0] != "" {
		props.HasLAPS = true
	}
	return ComputerEntry{
		ObjectIdentifier:  n.ObjectIdentifier,
		AllowedToDelegate: []TypedPrincipal{},
		AllowedToAct:      []TypedPrincipal{},
		Sessions:          SessionData{Results: []TypedSession{}, Collected: false},
		PrivilegedSessions: SessionData{Results: []TypedSession{}, Collected: false},
		RegistrySessions:  SessionData{Results: []TypedSession{}, Collected: false},
		LocalGroups:       []LocalGroup{},
		UserRights:        []UserRight{},
		Aces:              n.Aces,
		IsACLProtected:    n.IsACLProtected,
		Properties:        props,
	}
}

func nodeToDomainEntry(n Node) DomainEntry {
	return DomainEntry{
		ObjectIdentifier: n.ObjectIdentifier,
		Trusts:           []DomainTrust{},
		ChildObjects:     []TypedPrincipal{},
		Aces:             n.Aces,
		IsACLProtected:   n.IsACLProtected,
		Properties:       n.Properties,
		Links:            []GPOLink{},
	}
}

func enrichCertTemplateProperties(n Node) Properties {
	p := n.Properties
	raw := p.RawAttributes
	// msPKI-Certificate-Name-Flag bit 1 = ENROLLEE_SUPPLIES_SUBJECT
	if v := raw["msPKI-Certificate-Name-Flag"]; len(v) > 0 {
		flag := parseInt64(v[0])
		p.EnrolleeSuppliesSubject = (flag & 0x00000001) != 0
	}
	// msPKI-Enrollment-Flag bit 2 = REQUIRE_CA_MANAGER_APPROVAL (pend)
	if v := raw["msPKI-Enrollment-Flag"]; len(v) > 0 {
		flag := parseInt64(v[0])
		p.RequiresManagerApproval = (flag & 0x00000002) != 0
	}
	p.EKUs = raw["pKIExtendedKeyUsage"]
	return p
}

func parseSPNTargets(spns []string) []SPNTarget {
	var targets []SPNTarget
	for _, spn := range spns {
		// SPN format: ServiceClass/Host[:Port][:InstanceName]
		// e.g. "MSSQLSvc/dc01.corp.local:1433" or "HTTP/webserver"
		service, host := extractSPNParts(spn)
		targets = append(targets, SPNTarget{
			// ComputerSID should be the SID of the target computer.
			// We don't have it here without a secondary LDAP lookup, so leave
			// empty — BloodHound CE accepts empty and creates a dangling-but-harmless
			// node rather than a broken edge pointing at a non-existent SID.
			ComputerSID: "",
			Port:        0,
			Service:     service + "/" + host,
		})
	}
	return targets
}

// extractSPNParts splits "ServiceClass/Host:Port" into (service, host).
func extractSPNParts(spn string) (service, host string) {
	slash := strings.Index(spn, "/")
	if slash < 0 {
		return spn, ""
	}
	service = spn[:slash]
	rest := spn[slash+1:]
	// strip :port or :instance suffix from host
	if colon := strings.Index(rest, ":"); colon >= 0 {
		host = rest[:colon]
	} else {
		host = rest
	}
	return service, host
}


func parseInt64(s string) int64 {
	v := int64(0)
	for _, c := range s {
		if c >= '0' && c <= '9' {
			v = v*10 + int64(c-'0')
		}
	}
	return v
}

package bh

// ADData contains all collected Active Directory objects, ready for BH formatting.
type ADData struct {
	Users         []Node
	Groups        []Node
	Computers     []Node
	Domains       []Node
	GPOs          []Node
	OUs           []Node
	CertTemplates []Node
	EnterpriseCAs []Node
}

// Node is a universal AD object that maps to any BloodHound entity type.
type Node struct {
	ObjectIdentifier string     `json:"ObjectIdentifier"`
	ObjectType       string     `json:"-"` // internal only
	Properties       Properties `json:"Properties"`
	Aces             []ACE      `json:"Aces,omitempty"`
	IsDeleted        bool       `json:"IsDeleted,omitempty"`
	IsACLProtected   bool       `json:"IsACLProtected,omitempty"`
}

// Properties holds the BloodHound CE v6 property bag for any object type.
type Properties struct {
	Name              string   `json:"name"`
	Domain            string   `json:"domain"`
	DomainSID         string   `json:"domainsid,omitempty"`
	Description       string   `json:"description,omitempty"`
	DistinguishedName string   `json:"distinguishedname,omitempty"`
	HighValue         bool     `json:"highvalue"`
	AdminCount        bool     `json:"admincount,omitempty"`
	// User/Computer shared
	Enabled             bool     `json:"enabled,omitempty"`
	PasswordLastSet     int64    `json:"pwdlastset,omitempty"`
	LastLogon           int64    `json:"lastlogon,omitempty"`
	LastLogonTimestamp  int64    `json:"lastlogontimestamp,omitempty"`
	// User specific
	SAMAccountName        string   `json:"samaccountname,omitempty"`
	ServicePrincipalNames []string `json:"serviceprincipalnames,omitempty"`
	HasSPN                bool     `json:"hasspn,omitempty"`
	DontReqPreAuth        bool     `json:"dontreqpreauth,omitempty"`
	UnconstrainedDelegation bool   `json:"unconstraineddelegation,omitempty"`
	// Computer specific
	OperatingSystem        string `json:"operatingsystem,omitempty"`
	OperatingSystemVersion string `json:"operatingsystemversion,omitempty"`
	HasLAPS                bool   `json:"haslaps,omitempty"`
	// Membership relations (kept as raw DN strings for BH processing)
	Members  []string `json:"members,omitempty"`
	MemberOf []string `json:"memberof,omitempty"`
	// ADCS specific
	CertTemplateOID         string   `json:"certtemplateoid,omitempty"`
	RequiresManagerApproval bool     `json:"requiresmanagerapproval,omitempty"`
	EnrolleeSuppliesSubject bool     `json:"enrolleesuppliessubject,omitempty"`
	EKUs                    []string `json:"ekus,omitempty"`
	// Internal: all raw attributes for completeness (not emitted to BH JSON)
	RawAttributes map[string][]string `json:"-"`
}

// ACE represents an Access Control Entry on an AD object.
type ACE struct {
	PrincipalSID  string `json:"PrincipalSID"`
	PrincipalType string `json:"PrincipalType"`
	RightName     string `json:"RightName"`
	IsInherited   bool   `json:"IsInherited"`
}

// ---- BloodHound CE v6 JSON output envelopes ----

// UserFile is the top-level BH CE v6 JSON structure for users.json
type UserFile struct {
	Data []UserEntry `json:"data"`
	Meta FileMeta    `json:"meta"`
}

// GroupFile is the top-level BH CE v6 JSON structure for groups.json
type GroupFile struct {
	Data []GroupEntry `json:"data"`
	Meta FileMeta     `json:"meta"`
}

// ComputerFile is the top-level BH CE v6 JSON structure for computers.json
type ComputerFile struct {
	Data []ComputerEntry `json:"data"`
	Meta FileMeta        `json:"meta"`
}

// DomainFile is the top-level BH CE v6 JSON structure for domains.json
type DomainFile struct {
	Data []DomainEntry `json:"data"`
	Meta FileMeta      `json:"meta"`
}

// GPOFile is the top-level BH CE v6 JSON structure for gpos.json
type GPOFile struct {
	Data []GPOEntry `json:"data"`
	Meta FileMeta   `json:"meta"`
}

// OUFile is the top-level BH CE v6 JSON structure for ous.json
type OUFile struct {
	Data []OUEntry `json:"data"`
	Meta FileMeta  `json:"meta"`
}

// CertTemplateFile is the top-level BH CE v6 JSON structure for certtemplates.json
type CertTemplateFile struct {
	Data []CertTemplateEntry `json:"data"`
	Meta FileMeta            `json:"meta"`
}

// EnterpriseCAFile is the top-level BH CE v6 JSON structure for enterprisecas.json
type EnterpriseCAFile struct {
	Data []EnterpriseCAEntry `json:"data"`
	Meta FileMeta            `json:"meta"`
}

// FileMeta contains the metadata block required by every BH CE v6 file.
type FileMeta struct {
	Methods int    `json:"methods"`
	Type    string `json:"type"`
	Count   int    `json:"count"`
	Version int    `json:"version"`
}

// ---- Per-type entry wrappers (BH CE v6 structure) ----

type UserEntry struct {
	ObjectIdentifier          string              `json:"ObjectIdentifier"`
	AllowedToDelegate         []TypedPrincipal    `json:"AllowedToDelegate"`
	PrimaryGroupSID           string              `json:"PrimaryGroupSID,omitempty"`
	HasSIDHistory             []TypedPrincipal    `json:"HasSIDHistory"`
	SPNTargets                []SPNTarget         `json:"SPNTargets"`
	Aces                      []ACE               `json:"Aces"`
	IsACLProtected            bool                `json:"IsACLProtected"`
	Properties                Properties          `json:"Properties"`
}

type GroupEntry struct {
	ObjectIdentifier string           `json:"ObjectIdentifier"`
	Members          []TypedPrincipal `json:"Members"`
	Aces             []ACE            `json:"Aces"`
	IsACLProtected   bool             `json:"IsACLProtected"`
	Properties       Properties       `json:"Properties"`
}

type ComputerEntry struct {
	ObjectIdentifier          string              `json:"ObjectIdentifier"`
	AllowedToDelegate         []TypedPrincipal    `json:"AllowedToDelegate"`
	AllowedToAct              []TypedPrincipal    `json:"AllowedToAct"`
	Sessions                  SessionData         `json:"Sessions"`
	PrivilegedSessions        SessionData         `json:"PrivilegedSessions"`
	RegistrySessions          SessionData         `json:"RegistrySessions"`
	LocalGroups               []LocalGroup        `json:"LocalGroups"`
	UserRights                []UserRight         `json:"UserRights"`
	Aces                      []ACE               `json:"Aces"`
	IsACLProtected            bool                `json:"IsACLProtected"`
	Properties                Properties          `json:"Properties"`
}

type DomainEntry struct {
	ObjectIdentifier string           `json:"ObjectIdentifier"`
	Trusts           []DomainTrust    `json:"Trusts"`
	ChildObjects     []TypedPrincipal `json:"ChildObjects"`
	Aces             []ACE            `json:"Aces"`
	IsACLProtected   bool             `json:"IsACLProtected"`
	Properties       Properties       `json:"Properties"`
	Links            []GPOLink        `json:"Links"`
}

type GPOEntry struct {
	ObjectIdentifier string     `json:"ObjectIdentifier"`
	Aces             []ACE      `json:"Aces"`
	IsACLProtected   bool       `json:"IsACLProtected"`
	Properties       Properties `json:"Properties"`
}

type OUEntry struct {
	ObjectIdentifier string           `json:"ObjectIdentifier"`
	ChildObjects     []TypedPrincipal `json:"ChildObjects"`
	Links            []GPOLink        `json:"Links"`
	Aces             []ACE            `json:"Aces"`
	IsACLProtected   bool             `json:"IsACLProtected"`
	Properties       Properties       `json:"Properties"`
}

type CertTemplateEntry struct {
	ObjectIdentifier string     `json:"ObjectIdentifier"`
	Aces             []ACE      `json:"Aces"`
	IsACLProtected   bool       `json:"IsACLProtected"`
	Properties       Properties `json:"Properties"`
}

type EnterpriseCAEntry struct {
	ObjectIdentifier  string              `json:"ObjectIdentifier"`
	EnabledCertTemplates []TypedPrincipal `json:"EnabledCertTemplates"`
	Aces              []ACE               `json:"Aces"`
	IsACLProtected    bool                `json:"IsACLProtected"`
	HostingComputer   string              `json:"HostingComputer,omitempty"`
	Properties        Properties          `json:"Properties"`
}

// ---- Supporting types ----

type TypedPrincipal struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

type SPNTarget struct {
	ComputerSID string `json:"ComputerSID"`
	Port        int    `json:"Port"`
	Service     string `json:"Service"`
}

type DomainTrust struct {
	TargetDomainSID  string `json:"TargetDomainSid"`
	TargetDomainName string `json:"TargetDomainName"`
	IsTransitive     bool   `json:"IsTransitive"`
	SidFilteringEnabled bool `json:"SidFilteringEnabled"`
	TrustDirection   int    `json:"TrustDirection"`
	TrustType        string `json:"TrustType"`
}

type SessionData struct {
	Results    []TypedSession `json:"Results"`
	Collected  bool           `json:"Collected"`
	FailureReason string      `json:"FailureReason,omitempty"`
}

type TypedSession struct {
	UserSID     string `json:"UserSID"`
	ComputerSID string `json:"ComputerSID"`
}

type LocalGroup struct {
	ObjectIdentifier string           `json:"ObjectIdentifier"`
	Name             string           `json:"Name"`
	Results          []TypedPrincipal `json:"Results"`
	Collected        bool             `json:"Collected"`
}

type UserRight struct {
	Privilege string           `json:"Privilege"`
	Results   []TypedPrincipal `json:"Results"`
	Collected bool             `json:"Collected"`
}

type GPOLink struct {
	GUID        string `json:"GUID"`
	IsEnforced  bool   `json:"IsEnforced"`
}

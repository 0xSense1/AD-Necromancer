package bloodhound

// Common type definitions for BloodHound data

type BloodHoundData struct {
	Users         []Node `json:"users"`
	Groups        []Node `json:"groups"`
	Computers     []Node `json:"computers"`
	Domains       []Node `json:"domains"`
	GPOs          []Node `json:"gpos"`
	OUs           []Node `json:"ous"`
	Containers    []Node `json:"containers"`
	CertTemplates []Node `json:"certtemplates"`
	EnterpriseCAs []Node `json:"enterprisecas"`
}

type Node struct {
	ObjectIdentifier string     `json:"ObjectIdentifier"`
	Properties       Properties `json:"Properties"`
	Aces             []Ace      `json:"Aces,omitempty"`
	IsDeleted        bool       `json:"IsDeleted,omitempty"`
}

type Properties struct {
	Name              string `json:"name"`
	Domain            string `json:"domain"`
	Description       string `json:"description"`
	DistinguishedName string `json:"distinguishedname"`
	HighValue         bool   `json:"highvalue"`
	AdminCount        bool   `json:"admincount"`
	// User specific
	Enabled         bool  `json:"enabled,omitempty"`
	PasswordLastSet int64 `json:"pwdlastset,omitempty"`
	// Computer specific
	OperatingSystem string `json:"operatingsystem,omitempty"`
}

type Ace struct {
	PrincipalSID  string `json:"PrincipalSID"`
	PrincipalType string `json:"PrincipalType"`
	RightName     string `json:"RightName"`
	IsInherited   bool   `json:"IsInherited"`
}

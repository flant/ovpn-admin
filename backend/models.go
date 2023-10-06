package backend

import (
	"io/fs"
	"sync"

	"github.com/pashcovich/openvpn-user/src"
	"github.com/prometheus/client_golang/prometheus"
)

type OvpnAdmin struct {
	Role                   string
	LastSyncTime           string
	LastSuccessfulSyncTime string
	MasterHostBasicAuth    bool
	MasterSyncToken        string
	clients                []OpenvpnClient
	activeClients          []ClientStatus
	PromRegistry           *prometheus.Registry
	OUser                  *src.OpenvpnUser
	KubeClient             *OpenVPNPKI
	MgmtInterfaces         map[string]string
	Templates              fs.FS
	Modules                []string
	mgmtStatusTimeFormat   string
	CreateUserMutex        *sync.Mutex
	ExtraAuth				bool
}

type OpenvpnServer struct {
	Host     string
	Port     string
	Protocol string
}

type openvpnClientConfig struct {
	Hosts      []OpenvpnServer
	CA         string
	Cert       string
	Key        string
	TLS        string
	PasswdAuth bool
}

type OpenvpnClient struct {
	Identity         string `json:"Identity"`
	AccountStatus    string `json:"AccountStatus"`
	ExpirationDate   string `json:"ExpirationDate"`
	RevocationDate   string `json:"RevocationDate"`
	ConnectionStatus string `json:"ConnectionStatus"`
	Connections      int    `json:"Connections"`
	SecondFactor     string   `json:"SecondFactor,omitempty"`
}

type ccdRoute struct {
	Address     string `json:"Address"`
	Mask        string `json:"Mask"`
	Description string `json:"Description"`
}

type CCD struct {
	User          string     `json:"User"`
	ClientAddress string     `json:"ClientAddress"`
	CustomRoutes  []ccdRoute `json:"CustomRoutes"`
}

type indexTxtLine struct {
	Flag              string
	ExpirationDate    string
	RevocationDate    string
	SerialNumber      string
	Filename          string
	DistinguishedName string
	Identity          string
}

type ClientStatus struct {
	CommonName              string
	RealAddress             string
	BytesReceived           string
	BytesSent               string
	ConnectedSince          string
	VirtualAddress          string
	LastRef                 string
	ConnectedSinceFormatted string
	LastRefFormatted        string
	ConnectedTo             string
}

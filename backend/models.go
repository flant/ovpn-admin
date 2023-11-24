package backend

import (
	"io/fs"
	"sync"
	"bytes"
	"time"
	"crypto/rsa"
	"crypto/x509"
	
	"k8s.io/client-go/kubernetes"
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
	PKI                     *OpenVPNPKI
	MgmtInterfaces         map[string]string
	Templates              fs.FS
	Modules                []string
	mgmtStatusTimeFormat   string
	CreateUserMutex        *sync.Mutex
	ExtraAuth              bool
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

type OpenVPNPKI struct {
	CAPrivKeyRSA     *rsa.PrivateKey
	CAPrivKeyPEM     *bytes.Buffer
	CACert           *x509.Certificate
	CACertPEM        *bytes.Buffer
	ServerPrivKeyRSA *rsa.PrivateKey
	ServerPrivKeyPEM *bytes.Buffer
	ServerCert       *x509.Certificate
	ServerCertPEM    *bytes.Buffer
	TaKey       *bytes.Buffer
	DhParam          *bytes.Buffer
	ClientCerts      []ClientCert
	RevokedCerts     []RevokedCert
	KubeClient       *kubernetes.Clientset
}

type ClientCert struct {
	PrivKeyRSA *rsa.PrivateKey
	PrivKeyPEM *bytes.Buffer
	Cert       *x509.Certificate
	CertPEM    *bytes.Buffer
}

type RevokedCert struct {
	RevokedTime time.Time         `json:"revokedTime"`
	CommonName  string            `json:"commonName"`
	Cert        *x509.Certificate `json:"cert"`
}
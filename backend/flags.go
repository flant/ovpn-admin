package backend

import "gopkg.in/alecthomas/kingpin.v2"

var (
	ListenHost = kingpin.Flag("listen.host", "host for ovpn-admin").Default("0.0.0.0").Envar("OVPN_LISTEN_HOST").String()
	ListenPort = kingpin.Flag("listen.port", "port for ovpn-admin").Default("8080").Envar("OVPN_LISTEN_PORT").String()
	ServerRole = kingpin.Flag("role", "server role, master or slave").Default("master").Envar("OVPN_ROLE").HintOptions("master", "slave").String()

	//PersonalAccess       = kingpin.Flag("personalize", "personalize access for users").Default("false").Envar("OVPN_ADMIN_PERSONALIZE").Bool()
	//AdminUserPassword    = kingpin.Flag("admin.password", "password fom admin user").Default("admin").Envar("OVPN_ADMIN_PASSWORD").String()
	//AdditionalAdminUsers = kingpin.Flag("admin.users", "comma separated users for additional admin grants").Default("").Envar("OVPN_ADMIN_USERS").String()

	masterHost              = kingpin.Flag("master.host", "URL for the master server").Default("http://127.0.0.1").Envar("OVPN_MASTER_HOST").String()
	MasterBasicAuthUser     = kingpin.Flag("master.basic-auth.user", "user for master server's Basic Auth").Default("").Envar("OVPN_MASTER_USER").String()
	MasterBasicAuthPassword = kingpin.Flag("master.basic-auth.password", "password for master server's Basic Auth").Default("").Envar("OVPN_MASTER_PASSWORD").String()
	masterSyncFrequency     = kingpin.Flag("master.sync-frequency", "master host data sync frequency in seconds").Default("600").Envar("OVPN_MASTER_SYNC_FREQUENCY").Int()
	MasterSyncToken         = kingpin.Flag("master.sync-token", "master host data sync security token").Default("VerySecureToken").Envar("OVPN_MASTER_TOKEN").PlaceHolder("TOKEN").String()

	openvpnNetwork = kingpin.Flag("ovpn.network", "NETWORK/MASK_PREFIX for OpenVPN server").Default("172.16.100.0/24").Envar("OVPN_NETWORK").String()
	openvpnServer  = kingpin.Flag("ovpn.server", "HOST:PORT:PROTOCOL for OpenVPN server; can have multiple values").Default("127.0.0.1:7777:tcp").Envar("OVPN_SERVER").PlaceHolder("HOST:PORT:PROTOCOL").Strings()
	//openvpnServerCryptoMode = kingpin.Flag("ovpn.server.crypto-mode", "OpenVPN server crypto mode").Default("tls-auth").Envar("OVPN_SERVER_CRYPTO_MODE").HintOptions("none", "tls-auth", "tls-crypt", "tls-cryptv2").Strings()
	//openvpnServerCryptoFile = kingpin.Flag("ovpn.server.crypto-file", "OpenVPN server file name with cert for crypto ").Default("ta.key").Envar("OVPN_SERVER_CRYPTO_FILE").Strings()
	openvpnServerBehindLB = kingpin.Flag("ovpn.server.behindLB", "enable if your OpenVPN server is behind Kubernetes Service having the LoadBalancer type").Default("false").Envar("OVPN_LB").Bool()
	openvpnServiceName    = kingpin.Flag("ovpn.service", "the name of Kubernetes Service having the LoadBalancer type if your OpenVPN server is behind it").Default("openvpn-external").Envar("OVPN_LB_SERVICE").Strings()

	MgmtAddress = kingpin.Flag("mgmt", "ALIAS=HOST:PORT for OpenVPN server mgmt interface; can have multiple values").Default("main=127.0.0.1:8989").Envar("OVPN_MGMT").Strings()
	MetricsPath = kingpin.Flag("metrics.path", "URL path for exposing collected metrics").Default("/metrics").Envar("OVPN_METRICS_PATH").String()

	EasyrsaDirPath = kingpin.Flag("easyrsa.path", "path to easyrsa dir").Default("./easyrsa").Envar("EASYRSA_PATH").String()
	IndexTxtPath   = kingpin.Flag("easyrsa.index-path", "path to easyrsa index file").Default("").Envar("OVPN_INDEX_PATH").String()

	CcdEnabled = kingpin.Flag("ccd", "enable client-config-dir").Default("false").Envar("OVPN_CCD").Bool()
	CcdDir     = kingpin.Flag("ccd.path", "path to client-config-dir").Default("./ccd").Envar("OVPN_CCD_PATH").String()

	clientConfigTemplatePath = kingpin.Flag("templates.clientconfig-path", "path to custom client.conf.tpl").Default("").Envar("OVPN_TEMPLATES_CC_PATH").String()
	ccdTemplatePath          = kingpin.Flag("templates.ccd-path", "path to custom ccd.tpl").Default("").Envar("OVPN_TEMPLATES_CCD_PATH").String()

	AuthType	   = kingpin.Flag("auth.type", "auth type").Default("").Envar("OVPN_AUTH").HintOptions("TOTP", "PASSWORD", "").String()
	AuthDatabase   = kingpin.Flag("auth.db", "database path for password authentication").Default("./easyrsa/pki/users.db").Envar("OVPN_AUTH_DB_PATH").String()

	LogLevel  = kingpin.Flag("log.level", "set log level: trace, debug, info, warn, error (default info)").Default("info").Envar("LOG_LEVEL").String()
	LogFormat = kingpin.Flag("log.format", "set log format: text, json (default text)").Default("text").Envar("LOG_FORMAT").String()

	StorageBackend = kingpin.Flag("storage.backend", "storage backend for user certs)").Default("filesystem").HintOptions("kubernetes.secrets", "filesystem").Envar("STORAGE_BACKEND").String()
)

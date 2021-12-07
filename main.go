package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/gobuffalo/packr/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	usernameRegexp       = `^([a-zA-Z0-9_.-@])+$`
	passwordRegexp       = `^([a-zA-Z0-9_.-@])+$`
	passwordMinLength    = 6
	certsArchiveFileName = "certs.tar.gz"
	ccdArchiveFileName   = "ccd.tar.gz"
	indexTxtDateLayout   = "060102150405Z"
	stringDateFormat     = "2006-01-02 15:04:05"
	ovpnStatusDateLayout = "2006-01-02 15:04:05"
	downloadCertsApiUrl  = "api/data/certs/download"
	downloadCcdApiUrl    = "api/data/ccd/download"

	kubeTokenFilePath     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	kubeNamespaceFilePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

var (
	listenHost      				 = kingpin.Flag("listen.host","host for ovpn-admin").Default("0.0.0.0").Envar("OVPN_LISTEN_HOST").String()
	listenPort      				 = kingpin.Flag("listen.port","port for ovpn-admin").Default("8080").Envar("OVPN_LISTEN_PORT").String()
    listenBaseUrl                    = kingpin.Flag("listen.base-url", "base url for ovpn-admin").Default("/").Envar("OVPN_LISTEN_BASE_URL").String()
	serverRole               = kingpin.Flag("role","server role, master or slave").Default("master").Envar("OVPN_ROLE").HintOptions("master", "slave").String()
	masterHost               = kingpin.Flag("master.host","URL for the master server").Default("http://127.0.0.1").Envar("OVPN_MASTER_HOST").String()
	masterBasicAuthUser			 = kingpin.Flag("master.basic-auth.user","user for master server's Basic Auth").Default("").Envar("OVPN_MASTER_USER").String()
	masterBasicAuthPassword  = kingpin.Flag("master.basic-auth.password","password for master server's Basic Auth").Default("").Envar("OVPN_MASTER_PASSWORD").String()
	masterSyncFrequency      = kingpin.Flag("master.sync-frequency", "master host data sync frequency in seconds").Default("600").Envar("OVPN_MASTER_SYNC_FREQUENCY").Int()
	masterSyncToken          = kingpin.Flag("master.sync-token", "master host data sync security token").Default("VerySecureToken").Envar("OVPN_MASTER_TOKEN").PlaceHolder("TOKEN").String()
	openvpnNetwork           = kingpin.Flag("ovpn.network","NETWORK/MASK_PREFIX for OpenVPN server").Default("172.16.100.0/24").Envar("OVPN_NETWORK").String()
	openvpnServer      			 = kingpin.Flag("ovpn.server","HOST:PORT:PROTOCOL for OpenVPN server; can have multiple values").Default("127.0.0.1:7777:tcp").Envar("OVPN_SERVER").PlaceHolder("HOST:PORT:PROTOCOL").Strings()
	openvpnServerBehindLB 	 = kingpin.Flag("ovpn.server.behindLB","enable if your OpenVPN server is behind Kubernetes Service having the LoadBalancer type").Default("false").Envar("OVPN_LB").Bool()
	openvpnServiceName 			 = kingpin.Flag("ovpn.service","the name of Kubernetes Service having the LoadBalancer type if your OpenVPN server is behind it").Default("openvpn-external").Envar("OVPN_LB_SERVICE").String()
	mgmtAddress		    			 = kingpin.Flag("mgmt","ALIAS=HOST:PORT for OpenVPN server mgmt interface; can have multiple values").Default("main=127.0.0.1:8989").Envar("OVPN_MGMT").Strings()
	metricsPath 						 = kingpin.Flag("metrics.path",  "URL path for exposing collected metrics").Default("/metrics").Envar("OVPN_METRICS_PATH").String()
	easyrsaDirPath     			 = kingpin.Flag("easyrsa.path", "path to easyrsa dir").Default("./easyrsa/").Envar("EASYRSA_PATH").String()
	indexTxtPath    				 = kingpin.Flag("easyrsa.index-path", "path to easyrsa index file").Default("./easyrsa/pki/index.txt").Envar("OVPN_INDEX_PATH").String()
    easyrsaBinPath               = kingpin.Flag("easyrsa.bin-path", "path to easyrsa script").Default("easyrsa").Envar("EASYRSA_BIN_PATH").String()
	ccdEnabled  						 = kingpin.Flag("ccd", "enable client-config-dir").Default("false").Envar("OVPN_CCD").Bool()
	ccdDir          				 = kingpin.Flag("ccd.path", "path to client-config-dir").Default("./ccd").Envar("OVPN_CCD_PATH").String()
	clientConfigTemplatePath = kingpin.Flag("templates.clientconfig-path", "path to custom client.conf.tpl").Default("").Envar("OVPN_TEMPLATES_CC_PATH").String()
	ccdTemplatePath          = kingpin.Flag("templates.ccd-path", "path to custom ccd.tpl").Default("").Envar("OVPN_TEMPLATES_CCD_PATH").String()
	authByPassword 					 = kingpin.Flag("auth.password", "enable additional password authentication").Default("false").Envar("OVPN_AUTH").Bool()
	authDatabase 						 = kingpin.Flag("auth.db", "database path for password authentication").Default("./easyrsa/pki/users.db").Envar("OVPN_AUTH_DB_PATH").String()
	debug           				 = kingpin.Flag("debug", "enable debug mode").Default("false").Envar("OVPN_DEBUG").Bool()
	verbose           			 = kingpin.Flag("verbose", "enable verbose mode").Default("false").Envar("OVPN_VERBOSE").Bool()

	certsArchivePath         = "/tmp/" + certsArchiveFileName
	ccdArchivePath           = "/tmp/" + ccdArchiveFileName

	version = "1.7.5"
)

var (
)

var (
	ovpnServerCertExpire = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_server_cert_expire",
		Help: "openvpn server certificate expire time in days",
	},
	)

	ovpnServerCaCertExpire = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_server_ca_cert_expire",
		Help: "openvpn server CA certificate expire time in days",
	},
	)

	ovpnClientsTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_total",
		Help: "total openvpn users",
	},
	)

	ovpnClientsRevoked = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_revoked",
		Help: "revoked openvpn users",
	},
	)

	ovpnClientsExpired = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_expired",
		Help: "expired openvpn users",
	},
	)

	ovpnClientsConnected = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_connected",
		Help: "connected openvpn users",
	},
	)

	ovpnClientCertificateExpire = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_cert_expire",
		Help: "openvpn user certificate expire time in days",
	},
		[]string{"client"},
	)

	ovpnClientConnectionInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_connection_info",
		Help: "openvpn user connection info. ip - assigned address from ovpn network. value - last time when connection was refreshed in unix format",
	},
		[]string{"client", "ip"},
	)

	ovpnClientConnectionFrom = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_connection_from",
		Help: "openvpn user connection info. ip - from which address connection was initialized. value - time when connection was initialized in unix format",
	},
		[]string{"client", "ip"},
	)

	ovpnClientBytesReceived = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_bytes_received",
		Help: "openvpn user bytes received",
	},
		[]string{"client"},
	)

	ovpnClientBytesSent = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_bytes_sent",
		Help: "openvpn user bytes sent",
	},
		[]string{"client"},
	)
)

type OvpnAdmin struct {
	role                   string
	lastSyncTime           string
	lastSuccessfulSyncTime string
	masterHostBasicAuth    bool
	masterSyncToken        string
	clients                []OpenvpnClient
	activeClients          []clientStatus
	promRegistry           *prometheus.Registry
	mgmtInterfaces         map[string]string
	templates              *packr.Box
	modules                []string
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

	Identity            string      `json:"Identity"`
	AccountStatus       string      `json:"AccountStatus"`
	ExpirationDate      string      `json:"ExpirationDate"`
	RevocationDate      string      `json:"RevocationDate"`
	ConnectionStatus    string      `json:"ConnectionStatus"`
	ConnectionServer 	string      `json:"ConnectionServer"`

}

type ccdRoute struct {
	Address     string `json:"Address"`
	Mask        string `json:"Mask"`
	Description string `json:"Description"`
}

type Ccd struct {
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

type clientStatus struct {
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

func (oAdmin *OvpnAdmin) userListHandler(w http.ResponseWriter, r *http.Request) {
	usersList, _ := json.Marshal(oAdmin.clients)
	fmt.Fprintf(w, "%s", usersList)
}

func (oAdmin *OvpnAdmin) userStatisticHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	userStatistic, _ := json.Marshal(oAdmin.getUserStatistic(r.FormValue("username")))
	fmt.Fprintf(w, "%s", userStatistic)
}

func (oAdmin *OvpnAdmin) userCreateHandler(w http.ResponseWriter, r *http.Request) {
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	r.ParseForm()
	userCreated, userCreateStatus := oAdmin.userCreate(r.FormValue("username"), r.FormValue("password"))

	if userCreated {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, userCreateStatus)
		return
	} else {
		http.Error(w, userCreateStatus, http.StatusUnprocessableEntity)
	}
}

func (oAdmin *OvpnAdmin) userRevokeHandler(w http.ResponseWriter, r *http.Request) {
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	r.ParseForm()
	fmt.Fprintf(w, "%s", oAdmin.userRevoke(r.FormValue("username")))
}

func (oAdmin *OvpnAdmin) userUnrevokeHandler(w http.ResponseWriter, r *http.Request) {
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}

	r.ParseForm()
	fmt.Fprintf(w, "%s", oAdmin.userUnrevoke(r.FormValue("username")))
}

func (oAdmin *OvpnAdmin) userChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if *authByPassword {
		passwordChanged, passwordChangeMessage := oAdmin.userChangePassword(r.FormValue("username"), r.FormValue("password"))
		if passwordChanged {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"status":"ok", "message": "%s"}`, passwordChangeMessage)
			return
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"status":"error", "message": "%s"}`, passwordChangeMessage)
			return
		}
	} else {
		http.Error(w, `{"status":"error"}`, http.StatusNotImplemented)
	}

}

func (oAdmin *OvpnAdmin) userShowConfigHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	fmt.Fprintf(w, "%s", oAdmin.renderClientConfig(r.FormValue("username")))
}

func (oAdmin *OvpnAdmin) userDisconnectHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	// 	fmt.Fprintf(w, "%s", userDisconnect(r.FormValue("username")))
	fmt.Fprintf(w, "%s", r.FormValue("username"))
}

func (oAdmin *OvpnAdmin) userShowCcdHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	ccd, _ := json.Marshal(oAdmin.getCcd(r.FormValue("username")))
	fmt.Fprintf(w, "%s", ccd)
}

func (oAdmin *OvpnAdmin) userApplyCcdHandler(w http.ResponseWriter, r *http.Request) {
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	var ccd Ccd
	if r.Body == nil {
		http.Error(w, "Please send a request body", http.StatusBadRequest)
		return
	}

	err := json.NewDecoder(r.Body).Decode(&ccd)
	if err != nil {
		log.Println(err)
	}

	ccdApplied, applyStatus := oAdmin.modifyCcd(ccd)

	if ccdApplied {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, applyStatus)
		return
	} else {
		http.Error(w, applyStatus, http.StatusUnprocessableEntity)
	}
}

func (oAdmin *OvpnAdmin) serverSettingsHandler(w http.ResponseWriter, r *http.Request) {
	enabledModules, enabledModulesErr := json.Marshal(oAdmin.modules)
	if enabledModulesErr != nil {
		log.Printf("ERROR: %s\n", enabledModulesErr)
	}
	fmt.Fprintf(w, `{"status":"ok", "serverRole": "%s", "modules": %s }`, oAdmin.role, string(enabledModules))
}

func (oAdmin *OvpnAdmin) lastSyncTimeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, oAdmin.lastSyncTime)
}

func (oAdmin *OvpnAdmin) lastSuccessfulSyncTimeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, oAdmin.lastSuccessfulSyncTime)
}

func (oAdmin *OvpnAdmin) downloadCertsHandler(w http.ResponseWriter, r *http.Request) {
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	r.ParseForm()
	token := r.Form.Get("token")

	if token != oAdmin.masterSyncToken {
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return
	}

	archiveCerts()
	w.Header().Set("Content-Disposition", "attachment; filename="+certsArchiveFileName)
	http.ServeFile(w, r, certsArchivePath)
}

func (oAdmin *OvpnAdmin) downloadCcdHandler(w http.ResponseWriter, r *http.Request) {
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	r.ParseForm()
	token := r.Form.Get("token")

	if token != oAdmin.masterSyncToken {
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return
	}

	archiveCcd()
	w.Header().Set("Content-Disposition", "attachment; filename="+ccdArchiveFileName)
	http.ServeFile(w, r, ccdArchivePath)
}

func main() {
	kingpin.Version(version)
	kingpin.Parse()

	ovpnAdmin := new(OvpnAdmin)
	ovpnAdmin.lastSyncTime = "unknown"
	ovpnAdmin.role = *serverRole
	ovpnAdmin.lastSuccessfulSyncTime = "unknown"
	ovpnAdmin.masterSyncToken = *masterSyncToken
	ovpnAdmin.promRegistry = prometheus.NewRegistry()
	ovpnAdmin.modules = []string{}

	ovpnAdmin.mgmtInterfaces = make(map[string]string)

	for _, mgmtInterface := range *mgmtAddress {
		parts := strings.SplitN(mgmtInterface, "=", 2)
		ovpnAdmin.mgmtInterfaces[parts[0]] = parts[len(parts)-1]
	}

	ovpnAdmin.registerMetrics()
	ovpnAdmin.setState()

	go ovpnAdmin.updateState()

	if *masterBasicAuthPassword != "" && *masterBasicAuthUser != "" {
		ovpnAdmin.masterHostBasicAuth = true
	} else {
		ovpnAdmin.masterHostBasicAuth = false
	}

	ovpnAdmin.modules = append(ovpnAdmin.modules, "core")

	if *authByPassword {
		ovpnAdmin.modules = append(ovpnAdmin.modules, "passwdAuth")
	}

	if *ccdEnabled {
		ovpnAdmin.modules = append(ovpnAdmin.modules, "ccd")
	}

	if ovpnAdmin.role == "slave" {
		ovpnAdmin.syncDataFromMaster()
		go ovpnAdmin.syncWithMaster()
	}

	if *debug {
		log.Println("Runnnig in debug mode")
	}

	if *verbose {
		log.Println("Runnnig in verbose mode")
	}

	ovpnAdmin.templates = packr.New("template", "./templates")

	staticBox := packr.New("static", "./frontend/static")
	static := CacheControlWrapper(http.FileServer(staticBox))

	http.Handle(*listenBaseUrl, http.StripPrefix(strings.TrimRight(*listenBaseUrl, "/"), static))
	http.HandleFunc(*listenBaseUrl + "api/server/settings", ovpnAdmin.serverSettingsHandler)
	http.HandleFunc(*listenBaseUrl + "api/users/list", ovpnAdmin.userListHandler)
	http.HandleFunc(*listenBaseUrl + "api/user/create", ovpnAdmin.userCreateHandler)
	http.HandleFunc(*listenBaseUrl + "api/user/change-password", ovpnAdmin.userChangePasswordHandler)
	http.HandleFunc(*listenBaseUrl + "api/user/revoke", ovpnAdmin.userRevokeHandler)
	http.HandleFunc(*listenBaseUrl + "api/user/unrevoke", ovpnAdmin.userUnrevokeHandler)
	http.HandleFunc(*listenBaseUrl + "api/user/config/show", ovpnAdmin.userShowConfigHandler)
	http.HandleFunc(*listenBaseUrl + "api/user/disconnect", ovpnAdmin.userDisconnectHandler)
	http.HandleFunc(*listenBaseUrl + "api/user/statistic", ovpnAdmin.userStatisticHandler)
	http.HandleFunc(*listenBaseUrl + "api/user/ccd", ovpnAdmin.userShowCcdHandler)
	http.HandleFunc(*listenBaseUrl + "api/user/ccd/apply", ovpnAdmin.userApplyCcdHandler)

	http.HandleFunc(*listenBaseUrl + "api/sync/last/try", ovpnAdmin.lastSyncTimeHandler)
	http.HandleFunc(*listenBaseUrl + "api/sync/last/successful", ovpnAdmin.lastSuccessfulSyncTimeHandler)
	http.HandleFunc(*listenBaseUrl + downloadCertsApiUrl, ovpnAdmin.downloadCertsHandler)
	http.HandleFunc(*listenBaseUrl + downloadCcdApiUrl, ovpnAdmin.downloadCcdHandler)

	http.Handle(*metricsPath, promhttp.HandlerFor(ovpnAdmin.promRegistry, promhttp.HandlerOpts{}))
	http.HandleFunc(*listenBaseUrl + "ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "pong")
	})

	log.Printf("Bind: http://%s:%s%s\n", *listenHost, *listenPort, *listenBaseUrl)
	log.Fatal(http.ListenAndServe(*listenHost+":"+*listenPort, nil))
}

func CacheControlWrapper(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=2592000") // 30 days
		h.ServeHTTP(w, r)
	})
}

func (oAdmin *OvpnAdmin) registerMetrics() {
	oAdmin.promRegistry.MustRegister(ovpnServerCertExpire)
	oAdmin.promRegistry.MustRegister(ovpnServerCaCertExpire)
	oAdmin.promRegistry.MustRegister(ovpnClientsTotal)
	oAdmin.promRegistry.MustRegister(ovpnClientsRevoked)
	oAdmin.promRegistry.MustRegister(ovpnClientsConnected)
	oAdmin.promRegistry.MustRegister(ovpnClientsExpired)
	oAdmin.promRegistry.MustRegister(ovpnClientCertificateExpire)
	oAdmin.promRegistry.MustRegister(ovpnClientConnectionInfo)
	oAdmin.promRegistry.MustRegister(ovpnClientConnectionFrom)
	oAdmin.promRegistry.MustRegister(ovpnClientBytesReceived)
	oAdmin.promRegistry.MustRegister(ovpnClientBytesSent)
}

func (oAdmin *OvpnAdmin) setState() {
	oAdmin.activeClients = oAdmin.mgmtGetActiveClients()
	oAdmin.clients = oAdmin.usersList()

	ovpnServerCaCertExpire.Set(float64((getOvpnCaCertExpireDate().Unix() - time.Now().Unix()) / 3600 / 24))
}

func (oAdmin *OvpnAdmin) updateState() {
	for {
		time.Sleep(time.Duration(28) * time.Second)
		ovpnClientBytesSent.Reset()
		ovpnClientBytesReceived.Reset()
		ovpnClientConnectionFrom.Reset()
		ovpnClientConnectionInfo.Reset()
		go oAdmin.setState()
	}
}

func indexTxtParser(txt string) []indexTxtLine {
	var indexTxt []indexTxtLine

	txtLinesArray := strings.Split(txt, "\n")

	for _, v := range txtLinesArray {
		str := strings.Fields(v)
		if len(str) > 0 {
			switch {
			// case strings.HasPrefix(str[0], "E"):
			case strings.HasPrefix(str[0], "V"):
				indexTxt = append(indexTxt, indexTxtLine{Flag: str[0], ExpirationDate: str[1], SerialNumber: str[2], Filename: str[3], DistinguishedName: str[4], Identity: str[4][strings.Index(str[4], "=")+1:]})
			case strings.HasPrefix(str[0], "R"):
				indexTxt = append(indexTxt, indexTxtLine{Flag: str[0], ExpirationDate: str[1], RevocationDate: str[2], SerialNumber: str[3], Filename: str[4], DistinguishedName: str[5], Identity: str[5][strings.Index(str[5], "=")+1:]})
			}
		}
	}

	return indexTxt
}

func renderIndexTxt(data []indexTxtLine) string {
	indexTxt := ""
	for _, line := range data {
		switch {
		case line.Flag == "V":
			indexTxt += fmt.Sprintf("%s\t%s\t\t%s\t%s\t%s\n", line.Flag, line.ExpirationDate, line.SerialNumber, line.Filename, line.DistinguishedName)
		case line.Flag == "R":
			indexTxt += fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\n", line.Flag, line.ExpirationDate, line.RevocationDate, line.SerialNumber, line.Filename, line.DistinguishedName)
			// case line.flag == "E":
		}
	}
	return indexTxt
}

func (oAdmin *OvpnAdmin) getClientConfigTemplate() *template.Template {
	if *clientConfigTemplatePath != "" {
		return template.Must(template.ParseFiles(*clientConfigTemplatePath))
	} else {
		clientConfigTpl, clientConfigTplErr := oAdmin.templates.FindString("client.conf.tpl")
		if clientConfigTplErr != nil {
			log.Println("ERROR: clientConfigTpl not found in templates box")
		}
		return template.Must(template.New("client-config").Parse(clientConfigTpl))
	}
}

func (oAdmin *OvpnAdmin) renderClientConfig(username string) string {
	if checkUserExist(username) {
		var hosts []OpenvpnServer

		for _, server := range *openvpnServer {
			parts := strings.SplitN(server, ":", 3)
			hosts = append(hosts, OpenvpnServer{Host: parts[0], Port: parts[1], Protocol: parts[2]})
		}
		if *openvpnServerBehindLB {
			hosts = getOvpnServerHostsFromKubeApi()
		}

		if *debug {
			log.Printf("WARNING: hosts for %s\n %v", username, hosts)
		}

		conf := openvpnClientConfig{}
		conf.Hosts = hosts
		conf.CA = fRead(*easyrsaDirPath + "/pki/ca.crt")
		conf.Cert = fRead(*easyrsaDirPath + "/pki/issued/" + username + ".crt")
		conf.Key = fRead(*easyrsaDirPath + "/pki/private/" + username + ".key")
		conf.TLS = fRead(*easyrsaDirPath + "/pki/ta.key")
		conf.PasswdAuth = *authByPassword

		t := oAdmin.getClientConfigTemplate()

		var tmp bytes.Buffer
		err := t.Execute(&tmp, conf)
		if err != nil {
			log.Printf("ERROR: something goes wrong during rendering config for %s\n", username )
			if *debug {
				log.Printf("DEBUG: rendering config for %s failed with error %v\n", username, err )
			}
		}

		hosts = nil
		if *verbose {
			log.Printf("INFO: Rendered config for user %s: %+v\n", username, tmp.String())
		}
		return fmt.Sprintf("%+v\n", tmp.String())
	}
	log.Printf("WARNING: User \"%s\" not found", username)
	return fmt.Sprintf("User \"%s\" not found", username)
}

func (oAdmin *OvpnAdmin) getCcdTemplate() *template.Template {
	if *ccdTemplatePath != "" {
		return template.Must(template.ParseFiles(*ccdTemplatePath))
	} else {
		ccdTpl, ccdTplErr := oAdmin.templates.FindString("ccd.tpl")
		if ccdTplErr != nil {
			log.Printf("ERROR: ccdTpl not found in templates box")
		}
		return template.Must(template.New("ccd").Parse(ccdTpl))
	}
}

func (oAdmin *OvpnAdmin) parseCcd(username string) Ccd {
	ccd := Ccd{}
	ccd.User = username
	ccd.ClientAddress = "dynamic"
	ccd.CustomRoutes = []ccdRoute{}

	txtLinesArray := strings.Split(fRead(*ccdDir+"/"+username), "\n")

	for _, v := range txtLinesArray {
		str := strings.Fields(v)
		if len(str) > 0 {
			switch {
			case strings.HasPrefix(str[0], "ifconfig-push"):
				ccd.ClientAddress = str[1]
			case strings.HasPrefix(str[0], "push"):
				ccd.CustomRoutes = append(ccd.CustomRoutes, ccdRoute{Address: strings.Trim(str[2], "\""), Mask: strings.Trim(str[3], "\""), Description: strings.Trim(strings.Join(str[4:], ""), "#")})
			}
		}
	}

	return ccd
}

func (oAdmin *OvpnAdmin) modifyCcd(ccd Ccd) (bool, string) {
	ccdErr := "something goes wrong"

	if fCreate(*ccdDir + "/" + ccd.User) {
		ccdValid, ccdErr := validateCcd(ccd)
		if ccdErr != "" {
			return false, ccdErr
		}

		if ccdValid {
			t := oAdmin.getCcdTemplate()
			var tmp bytes.Buffer
			tplErr := t.Execute(&tmp, ccd)
			if tplErr != nil {
				log.Println(tplErr)
			}
			fWrite(*ccdDir+"/"+ccd.User, tmp.String())
			return true, "ccd updated successfully"
		}
	}

	return false, ccdErr
}

func validateCcd(ccd Ccd) (bool, string) {

    ccdErr := ""

    if ccd.ClientAddress != "dynamic" {
        _, ovpnNet, err := net.ParseCIDR(*openvpnNetwork)
        if err != nil {
		    log.Println(err)
	    }

	    if ! checkStaticAddressIsFree(ccd.ClientAddress, ccd.User) {
            ccdErr = fmt.Sprintf("ClientAddress \"%s\" already assigned to another user", ccd.ClientAddress)
            if *debug {
                log.Printf("ERROR: Modify ccd for user %s: %s\n", ccd.User, ccdErr)
            }
            return false, ccdErr
	    }

        if net.ParseIP(ccd.ClientAddress) == nil {
            ccdErr = fmt.Sprintf("ClientAddress \"%s\" not a valid IP address", ccd.ClientAddress)
            if *debug {
                log.Printf("ERROR: Modify ccd for user %s: %s\n",  ccd.User, ccdErr)
            }
            return false, ccdErr
        }

        if ! ovpnNet.Contains(net.ParseIP(ccd.ClientAddress)) {
            ccdErr = fmt.Sprintf("ClientAddress \"%s\" not belongs to openvpn server network", ccd.ClientAddress)
            if *debug {
                log.Printf("ERROR: Modify ccd for user %s: %s\n", ccd.User, ccdErr)
            }
            return false, ccdErr
        }
    }

    for _, route := range ccd.CustomRoutes {
        if net.ParseIP(route.Address) == nil {
            ccdErr = fmt.Sprintf("CustomRoute.Address \"%s\" must be a valid IP address", route.Address)
            if *debug {
                log.Printf("ERROR: Modify ccd for user %s: %s\n", ccd.User, ccdErr)
            }
            return false, ccdErr
        }

        if net.ParseIP(route.Mask) == nil {
            ccdErr = fmt.Sprintf("CustomRoute.Mask \"%s\" must be a valid IP address", route.Mask)
            if *debug {
                log.Printf("ERROR: Modify ccd for user %s: %s\n", ccd.User, ccdErr)
            }
            return false, ccdErr
        }
    }

	return true, ccdErr
}

func (oAdmin *OvpnAdmin) getCcd(username string) Ccd {
	ccd := Ccd{}
	ccd.User = username
	ccd.ClientAddress = "dynamic"
	ccd.CustomRoutes = []ccdRoute{}

	if fCreate(*ccdDir + "/" + username) {
		ccd = oAdmin.parseCcd(username)
	}
	return ccd
}

func checkStaticAddressIsFree(staticAddress string, username string) bool {
	o := runBash(fmt.Sprintf("grep -rl ' %s ' %s | grep -vx %s/%s | wc -l", staticAddress, *ccdDir, *ccdDir, username))

	if strings.TrimSpace(o) == "0" {
		return true
	}
	return false
}

func validateUsername(username string) bool {
	var validUsername = regexp.MustCompile(usernameRegexp)
	return validUsername.MatchString(username)
}

func validatePassword(password string) bool {
	if len(password) < passwordMinLength {
		return false
	} else {
		return true
	}
}

func checkUserExist(username string) bool {
	for _, u := range indexTxtParser(fRead(*indexTxtPath)) {
		if u.DistinguishedName == ("/CN=" + username) {
			return true
		}
	}
	return false
}

func (oAdmin *OvpnAdmin) usersList() []OpenvpnClient {
	var users []OpenvpnClient

	totalCerts := 0
	validCerts := 0
	revokedCerts := 0
	expiredCerts := 0
	connectedUsers := 0
	apochNow := time.Now().Unix()

	for _, line := range indexTxtParser(fRead(*indexTxtPath)) {
		if line.Identity != "server" {
			totalCerts += 1
			ovpnClient := OpenvpnClient{Identity: line.Identity, ExpirationDate: parseDateToString(indexTxtDateLayout, line.ExpirationDate, stringDateFormat)}
			switch {
			case line.Flag == "V":
				ovpnClient.AccountStatus = "Active"
				ovpnClientCertificateExpire.WithLabelValues(line.Identity).Set(float64((parseDateToUnix(indexTxtDateLayout, line.ExpirationDate) - apochNow) / 3600 / 24))
				validCerts += 1
			case line.Flag == "R":
				ovpnClient.AccountStatus = "Revoked"
				ovpnClient.RevocationDate = parseDateToString(indexTxtDateLayout, line.RevocationDate, stringDateFormat)
				ovpnClientCertificateExpire.WithLabelValues(line.Identity).Set(float64((parseDateToUnix(indexTxtDateLayout, line.ExpirationDate) - apochNow) / 3600 / 24))
				revokedCerts += 1
			case line.Flag == "E":
				ovpnClient.AccountStatus = "Expired"
				ovpnClientCertificateExpire.WithLabelValues(line.Identity).Set(float64((parseDateToUnix(indexTxtDateLayout, line.ExpirationDate) - apochNow) / 3600 / 24))
				expiredCerts += 1
			}

			ovpnClient.ConnectionServer = ""

			userConnected, userConnectedTo := isUserConnected(line.Identity, oAdmin.activeClients)
			if userConnected {
				ovpnClient.ConnectionStatus = "Connected"
				ovpnClient.ConnectionServer = userConnectedTo
				connectedUsers += 1
			}

			users = append(users, ovpnClient)

		} else {
			ovpnServerCertExpire.Set(float64((parseDateToUnix(indexTxtDateLayout, line.ExpirationDate) - apochNow) / 3600 / 24))
		}
	}

	otherCerts := totalCerts - validCerts - revokedCerts - expiredCerts

	if otherCerts != 0 {
		log.Printf("WARNING: there are %d otherCerts\n", otherCerts)
	}

	ovpnClientsTotal.Set(float64(totalCerts))
	ovpnClientsRevoked.Set(float64(revokedCerts))
	ovpnClientsExpired.Set(float64(expiredCerts))
	ovpnClientsConnected.Set(float64(connectedUsers))

	return users
}

func (oAdmin *OvpnAdmin) userCreate(username, password string) (bool, string) {
	ucErr := fmt.Sprintf("User \"%s\" created", username)

	if checkUserExist(username) {
		ucErr = fmt.Sprintf("User \"%s\" already exists\n", username)
		if *debug {
			log.Printf("ERROR: userCreate: %s\n", ucErr)
		}
		return false, ucErr
	}

	if !validateUsername(username) {
		ucErr = fmt.Sprintf("Username \"%s\" incorrect, you can use only %s\n", username, usernameRegexp)
		if *debug {
			log.Printf("ERROR: userCreate: %s\n", ucErr)
		}
		return false, ucErr
	}

	if *authByPassword {
		if !validatePassword(password) {
			ucErr = fmt.Sprintf("Password too short, password length must be greater or equal %d", passwordMinLength)
			if *debug {
				log.Printf("ERROR: userCreate: %s\n", ucErr)
			}
			return false, ucErr
		}
	}

	o := runBash(fmt.Sprintf("date +%%Y-%%m-%%d\\ %%H:%%M:%%S && cd %s && %s build-client-full %s nopass", *easyrsaDirPath, *easyrsaBinPath, username))
	log.Println(o)

	if *authByPassword {
		o = runBash(fmt.Sprintf("openvpn-user create --db.path %s --user %s --password %s", *authDatabase, username, password))
		log.Println(o)
	}

	if *verbose {
		log.Printf("INFO: user created: %s\n", username)
	}

	oAdmin.clients = oAdmin.usersList()

	return true, ucErr
}

func (oAdmin *OvpnAdmin) userChangePassword(username, password string) (bool, string) {

	if checkUserExist(username) {
		o := runBash(fmt.Sprintf("openvpn-user check --db.path %s --user %s | grep %s | wc -l", *authDatabase, username, username))
		log.Println(o)

		if !validatePassword(password) {
			ucpErr := fmt.Sprintf("Password for too short, password length must be greater or equal %d", passwordMinLength)
			if *debug {
				log.Printf("ERROR: userChangePassword: %s\n", ucpErr)
			}
			return false, ucpErr
		}

		if strings.TrimSpace(o) == "0" {
			log.Println("Creating user in users.db")
			o = runBash(fmt.Sprintf("openvpn-user create --db.path %s --user %s --password %s", *authDatabase, username, password))
			log.Println(o)
		}

		o = runBash(fmt.Sprintf("openvpn-user change-password --db.path %s --user %s --password %s", *authDatabase, username, password))
		log.Println(o)

		if *verbose {
			log.Printf("INFO: password for user %s was changed\n", username)
		}
		return true, "Password changed"
	}

	return false, "User does not exist"
}

func (oAdmin *OvpnAdmin) getUserStatistic(username string) clientStatus {
	for _, u := range oAdmin.activeClients {
		if u.CommonName == username {
			return u
		}
	}
	return clientStatus{}
}

func (oAdmin *OvpnAdmin) userRevoke(username string) string {
	if checkUserExist(username) {
		// check certificate valid flag 'V'
		o := runBash(fmt.Sprintf("date +%%Y-%%m-%%d\\ %%H:%%M:%%S && cd %s && echo yes | %s revoke %s && %s gen-crl", *easyrsaDirPath, *easyrsaBinPath, username, *easyrsaBinPath))
		if *authByPassword {
			o = runBash(fmt.Sprintf("openvpn-user revoke --db-path %s --user %s", *authDatabase, username))
			//fmt.Println(o)
		}

		crlFix()
		userConnected, userConnectedTo := isUserConnected(username, oAdmin.activeClients)
		if userConnected {
			oAdmin.mgmtKillUserConnection(username, userConnectedTo)
			log.Printf("Session for user \"%s\" session killed\n", username)
		}
		oAdmin.clients = oAdmin.usersList()
		return fmt.Sprintln(o)
	}
	log.Printf("User \"%s\" not found\n", username)
	return fmt.Sprintf("User \"%s\" not found", username)
}

func (oAdmin *OvpnAdmin) userUnrevoke(username string) string {
	if checkUserExist(username) {
		// check certificate revoked flag 'R'
		usersFromIndexTxt := indexTxtParser(fRead(*indexTxtPath))
		for i := range usersFromIndexTxt {
			if usersFromIndexTxt[i].DistinguishedName == ("/CN=" + username) {
				if usersFromIndexTxt[i].Flag == "R" {
					usersFromIndexTxt[i].Flag = "V"
					usersFromIndexTxt[i].RevocationDate = ""
					o := runBash(fmt.Sprintf("cd %s && cp pki/revoked/certs_by_serial/%s.crt pki/issued/%s.crt", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber, username))
					//fmt.Println(o)
					o = runBash(fmt.Sprintf("cd %s && cp pki/revoked/certs_by_serial/%s.crt pki/certs_by_serial/%s.pem", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber, usersFromIndexTxt[i].SerialNumber))
					//fmt.Println(o)
					o = runBash(fmt.Sprintf("cd %s && cp pki/revoked/private_by_serial/%s.key pki/private/%s.key", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber, username))
					//fmt.Println(o)
					o = runBash(fmt.Sprintf("cd %s && cp pki/revoked/reqs_by_serial/%s.req pki/reqs/%s.req", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber, username))
					//fmt.Println(o)
					fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
					//fmt.Print(renderIndexTxt(usersFromIndexTxt))
					o = runBash(fmt.Sprintf("cd %s && %s gen-crl", *easyrsaDirPath, *easyrsaBinPath))
					//fmt.Println(o)
					if *authByPassword {
						o = runBash(fmt.Sprintf("openvpn-user restore --db-path %s --user %s", *authDatabase, username))
						//fmt.Println(o)
					}
					crlFix()
					o = ""
					fmt.Println(o)
					break
				}
			}
		}
		fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
		fmt.Print(renderIndexTxt(usersFromIndexTxt))
		crlFix()
		oAdmin.clients = oAdmin.usersList()
		return fmt.Sprintf("{\"msg\":\"User %s successfully unrevoked\"}", username)
	}
	return fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
}

func (oAdmin *OvpnAdmin) mgmtRead(conn net.Conn) string {
	buf := make([]byte, 32768)
	bufLen, _ := conn.Read(buf)
	s := string(buf[:bufLen])
	return s
}

func (oAdmin *OvpnAdmin) mgmtConnectedUsersParser(text, serverName string) []clientStatus {
	var u []clientStatus
	isClientList := false
	isRouteTable := false
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		txt := scanner.Text()
		if regexp.MustCompile(`^Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since$`).MatchString(txt) {
			isClientList = true
			continue
		}
		if regexp.MustCompile(`^ROUTING TABLE$`).MatchString(txt) {
			isClientList = false
			continue
		}
		if regexp.MustCompile(`^Virtual Address,Common Name,Real Address,Last Ref$`).MatchString(txt) {
			isRouteTable = true
			continue
		}
		if regexp.MustCompile(`^GLOBAL STATS$`).MatchString(txt) {
			// isRouteTable = false // ineffectual assignment to isRouteTable (ineffassign)
			break
		}
		if isClientList {
			user := strings.Split(txt, ",")

			userName := user[0]
			userAddress := user[1]
			userBytesReceived := user[2]
			userBytesSent := user[3]
			userConnectedSince := user[4]

			userStatus := clientStatus{CommonName: userName, RealAddress: userAddress, BytesReceived: userBytesReceived, BytesSent: userBytesSent, ConnectedSince: userConnectedSince, ConnectedTo: serverName}
			u = append(u, userStatus)
			bytesSent, _ := strconv.Atoi(userBytesSent)
			bytesReceive, _ := strconv.Atoi(userBytesReceived)
			ovpnClientConnectionFrom.WithLabelValues(userName, userAddress).Set(float64(parseDateToUnix(ovpnStatusDateLayout, userConnectedSince)))
			ovpnClientBytesSent.WithLabelValues(userName).Set(float64(bytesSent))
			ovpnClientBytesReceived.WithLabelValues(userName).Set(float64(bytesReceive))
		}
		if isRouteTable {
			user := strings.Split(txt, ",")
			for i := range u {
				if u[i].CommonName == user[1] {
					u[i].VirtualAddress = user[0]
					u[i].LastRef = user[3]
					ovpnClientConnectionInfo.WithLabelValues(user[1], user[0]).Set(float64(parseDateToUnix(ovpnStatusDateLayout, user[3])))
					break
				}
			}
		}
	}
	return u
}

func (oAdmin *OvpnAdmin) mgmtKillUserConnection(username, serverName string) {
	conn, err := net.Dial("tcp", oAdmin.mgmtInterfaces[serverName])
	if err != nil {
		log.Printf("WARNING: openvpn mgmt interface for %s is not reachable by addr %s\n", serverName, oAdmin.mgmtInterfaces[serverName])
		return
	}
	oAdmin.mgmtRead(conn) // read welcome message
	conn.Write([]byte(fmt.Sprintf("kill %s\n", username)))
	fmt.Printf("%v", oAdmin.mgmtRead(conn))
	conn.Close()
}

func (oAdmin *OvpnAdmin) mgmtGetActiveClients() []clientStatus {
	var activeClients []clientStatus

	for srv, addr := range oAdmin.mgmtInterfaces {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			log.Printf("WARNING: openvpn mgmt interface for %s is not reachable by addr %s\n", srv, addr)
			break
		}
		oAdmin.mgmtRead(conn) // read welcome message
		conn.Write([]byte("status\n"))
		activeClients = append(activeClients, oAdmin.mgmtConnectedUsersParser(oAdmin.mgmtRead(conn), srv)...)
		conn.Close()
	}
	return activeClients
}

func isUserConnected(username string, connectedUsers []clientStatus) (bool, string) {
	for _, connectedUser := range connectedUsers {
		if connectedUser.CommonName == username {
			return true, connectedUser.ConnectedTo
		}
	}
	return false, ""
}

func (oAdmin *OvpnAdmin) downloadCerts() bool {
	if fExist(certsArchivePath) {
		fDelete(certsArchivePath)
	}
	err := fDownload(certsArchivePath, *masterHost+*listenBaseUrl+downloadCertsApiUrl+"?token="+oAdmin.masterSyncToken, oAdmin.masterHostBasicAuth)
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}

func (oAdmin *OvpnAdmin) downloadCcd() bool {
	if fExist(ccdArchivePath) {
		fDelete(ccdArchivePath)
	}

	err := fDownload(ccdArchivePath, *masterHost+*listenBaseUrl+downloadCcdApiUrl+"?token="+oAdmin.masterSyncToken, oAdmin.masterHostBasicAuth)
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}

func archiveCerts() {
	o := runBash(fmt.Sprintf("cd %s && tar -czf %s *", *easyrsaDirPath+"/pki", certsArchivePath))
	fmt.Println(o)
}

func archiveCcd() {
	o := runBash(fmt.Sprintf("cd %s && tar -czf %s *", *ccdDir, ccdArchivePath))
	fmt.Println(o)
}

func unArchiveCerts() {
	runBash(fmt.Sprintf("mkdir -p %s", *easyrsaDirPath+"/pki"))
	o := runBash(fmt.Sprintf("cd %s && tar -xzf %s", *easyrsaDirPath+"/pki", certsArchivePath))
	fmt.Println(o)
}

func unArchiveCcd() {
	runBash(fmt.Sprintf("mkdir -p %s", *ccdDir))
	o := runBash(fmt.Sprintf("cd %s && tar -xzf %s", *ccdDir, ccdArchivePath))
	fmt.Println(o)
}

func (oAdmin *OvpnAdmin) syncDataFromMaster() {
	retryCountMax := 3
	certsDownloadFailed := true
	ccdDownloadFailed := true
	certsDownloadRetries := 0
	ccdDownloadRetries := 0

	for certsDownloadFailed && certsDownloadRetries < retryCountMax {
		certsDownloadRetries += 1
		log.Printf("Downloading certs archive from master. Attempt %d\n", certsDownloadRetries)
		if oAdmin.downloadCerts() {
			certsDownloadFailed = false
			log.Println("Decompression certs archive from master")
			unArchiveCerts()
		} else {
			log.Printf("WARNING: something goes wrong during downloading certs from master. Attempt %d\n", certsDownloadRetries)
		}
	}

	for ccdDownloadFailed && ccdDownloadRetries < retryCountMax {
		ccdDownloadRetries += 1
		log.Printf("Downloading ccd archive from master. Attempt %d\n", ccdDownloadRetries)
		if oAdmin.downloadCcd() {
			ccdDownloadFailed = false
			log.Println("Decompression ccd archive from master")
			unArchiveCcd()
		} else {
			log.Printf("WARNING: something goes wrong during downloading certs from master. Attempt %d\n", ccdDownloadRetries)
		}
	}

	oAdmin.lastSyncTime = time.Now().Format("2006-01-02 15:04:05")
	if !ccdDownloadFailed && !certsDownloadFailed {
		oAdmin.lastSuccessfulSyncTime = time.Now().Format("2006-01-02 15:04:05")
	}
}

func (oAdmin *OvpnAdmin) syncWithMaster() {
	for {
		time.Sleep(time.Duration(*masterSyncFrequency) * time.Second)
		oAdmin.syncDataFromMaster()
	}
}


func getOvpnServerHostsFromKubeApi() []OpenvpnServer {
	var hosts []OpenvpnServer
	var lbHost string

	config, err := rest.InClusterConfig()
	if err != nil {
		log.Printf("ERROR: %s\n", err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Printf("ERROR: %s\n", err.Error())
	}

	service, err := clientset.CoreV1().Services(fRead(kubeNamespaceFilePath)).Get(context.TODO(), *openvpnServiceName, metav1.GetOptions{})
	if err != nil {
		log.Printf("ERROR: %s\n", err.Error())
	}

	if *debug {
		log.Printf("Debug: service from kube api %v\n", service)
		log.Printf("Debug: service.Status from kube api %v\n", service.Status)
		log.Printf("Debug: service.Status.LoadBalancer from kube api %v\n", service.Status.LoadBalancer)
	}

	if service.Status.LoadBalancer.Ingress[0].Hostname != "" {
		lbHost = service.Status.LoadBalancer.Ingress[0].Hostname
	}
	if service.Status.LoadBalancer.Ingress[0].IP != "" {
		lbHost = service.Status.LoadBalancer.Ingress[0].IP
	}
	hosts = append(hosts, OpenvpnServer{lbHost,strconv.Itoa(int(service.Spec.Ports[0].Port)),strings.ToLower(string(service.Spec.Ports[0].Protocol))})

	return hosts
}

func getOvpnCaCertExpireDate() time.Time {
	caCertPath := *easyrsaDirPath + "/pki/ca.crt"
	caCertExpireDate := runBash(fmt.Sprintf("openssl x509 -in %s -noout -enddate | awk -F \"=\" {'print $2'}", caCertPath))

	dateLayout := "Jan 2 15:04:05 2006 MST"
	t, err := time.Parse(dateLayout, strings.TrimSpace(caCertExpireDate))
	if err != nil {
		log.Printf("WARNING: can`t parse expire date for CA cert: %v\n", err)
		return time.Now()
	}

	return t
}

// https://community.openvpn.net/openvpn/ticket/623
func crlFix() {
	err1 := os.Chmod(*easyrsaDirPath+"/pki", 0755)
	if err1 != nil {
		log.Println(err1)
	}
	err2 := os.Chmod(*easyrsaDirPath+"/pki/crl.pem", 0644)
	if err2 != nil {
		log.Println(err2)
	}
}

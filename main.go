package main

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"sync"

	"github.com/flant/ovpn-admin/backend"
	_ "github.com/mattn/go-sqlite3"
	ou "github.com/pashcovich/openvpn-user/src"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	version = "2.1.0"
)

var logLevels = map[string]log.Level{
	"trace": log.TraceLevel,
	"debug": log.DebugLevel,
	"info":  log.InfoLevel,
	"warn":  log.WarnLevel,
	"error": log.ErrorLevel,
}

var logFormats = map[string]log.Formatter{
	"text": &log.TextFormatter{},
	"json": &log.JSONFormatter{},
}

//go:embed frontend/static
var staticFS embed.FS

//go:embed templates
var templatesFS embed.FS

func main() {
	kingpin.Version(version)
	kingpin.Parse()

	log.SetLevel(logLevels[*backend.LogLevel])
	log.SetFormatter(logFormats[*backend.LogFormat])

	ovpnAdmin := new(backend.OvpnAdmin)
	ovpnAdmin.OUser = new(ou.OpenvpnUser)

	if *backend.StorageBackend == "kubernetes.secrets" {
		ovpnAdmin.KubeClient = new(backend.OpenVPNPKI)
		err := ovpnAdmin.KubeClient.Run()
		if err != nil {
			log.Error(err)
		}
	}

	if *backend.IndexTxtPath == "" {
		*backend.IndexTxtPath = *backend.EasyrsaDirPath + "/pki/index.txt"
	}

	ovpnAdmin.LastSyncTime = "unknown"
	ovpnAdmin.Role = *backend.ServerRole
	ovpnAdmin.LastSuccessfulSyncTime = "unknown"
	ovpnAdmin.MasterSyncToken = *backend.MasterSyncToken
	ovpnAdmin.PromRegistry = prometheus.NewRegistry()
	ovpnAdmin.Modules = []string{}
	ovpnAdmin.CreateUserMutex = &sync.Mutex{}
	ovpnAdmin.MgmtInterfaces = make(map[string]string)

	for _, mgmtInterface := range *backend.MgmtAddress {
		parts := strings.SplitN(mgmtInterface, "=", 2)
		ovpnAdmin.MgmtInterfaces[parts[0]] = parts[len(parts)-1]
	}

	if *backend.MasterBasicAuthPassword != "" && *backend.MasterBasicAuthUser != "" {
		ovpnAdmin.MasterHostBasicAuth = true
	} else {
		ovpnAdmin.MasterHostBasicAuth = false
	}

	ovpnAdmin.Modules = append(ovpnAdmin.Modules, "core")

	switch *backend.AuthType {
	case "TOTP":
		ovpnAdmin.ExtraAuth = true
		ovpnAdmin.OUser.Database = backend.OpenDB(*backend.AuthDatabase)
		defer ovpnAdmin.OUser.Database.Close()
		ovpnAdmin.Modules = append(ovpnAdmin.Modules, "totpAuth")
	case "PASSWORD":
		ovpnAdmin.ExtraAuth = true
		ovpnAdmin.OUser.Database = backend.OpenDB(*backend.AuthDatabase)
		defer ovpnAdmin.OUser.Database.Close()
		ovpnAdmin.Modules = append(ovpnAdmin.Modules, "passwdAuth")
	}

	if *backend.CcdEnabled {
		ovpnAdmin.Modules = append(ovpnAdmin.Modules, "ccd")
	}

	if ovpnAdmin.Role == "slave" {
		ovpnAdmin.SyncDataFromMaster()
		go ovpnAdmin.SyncWithMaster()
	}

	templatesRoot, err := fs.Sub(templatesFS, "templates")
	if err != nil {
		log.Fatal(err)
	}

	staticRoot, err := fs.Sub(staticFS, "frontend/static")
	if err != nil {
		log.Fatal(err)
	}

	ovpnAdmin.Templates = templatesRoot
	static := CacheControlWrapper(http.FileServer(http.FS(staticRoot)))

	ovpnAdmin.MgmtSetTimeFormat()

	ovpnAdmin.RegisterMetrics()
	ovpnAdmin.SetState()

	go ovpnAdmin.UpdateState()

	http.Handle("/", static)
	http.HandleFunc("/api/server/settings", ovpnAdmin.ServerSettingsHandler)
	http.HandleFunc("/api/users/list", ovpnAdmin.UserListHandler)
	http.HandleFunc("/api/user/create", ovpnAdmin.UserCreateHandler)
	http.HandleFunc("/api/user/rotate", ovpnAdmin.UserRotateHandler)
	http.HandleFunc("/api/user/delete", ovpnAdmin.UserDeleteHandler)
	http.HandleFunc("/api/user/revoke", ovpnAdmin.UserRevokeHandler)
	http.HandleFunc("/api/user/unrevoke", ovpnAdmin.UserUnrevokeHandler)
	http.HandleFunc("/api/user/config/show", ovpnAdmin.UserShowConfigHandler)

	http.HandleFunc("/api/user/disconnect", ovpnAdmin.UserDisconnectHandler)
	http.HandleFunc("/api/user/statistic", ovpnAdmin.UserStatisticHandler)

	if *backend.CcdEnabled {
		http.HandleFunc("/api/user/ccd", ovpnAdmin.UserShowCcdHandler)
		http.HandleFunc("/api/user/ccd/apply", ovpnAdmin.UserApplyCcdHandler)
	}

	if ovpnAdmin.ExtraAuth {
		http.HandleFunc("/api/user/change-password", ovpnAdmin.UserChangePasswordHandler)
		http.HandleFunc("/api/auth/check", ovpnAdmin.AuthCheckHandler)
		if *backend.AuthType == "TOTP" {
			http.HandleFunc("/api/user/2fa/secret", ovpnAdmin.UserGetSecretHandler)
			http.HandleFunc("/api/user/2fa/register", ovpnAdmin.UserSetupTFAHandler)
			http.HandleFunc("/api/user/2fa/reset", ovpnAdmin.UserResetTFAHandler)
		}
	}

	http.HandleFunc("/api/sync/last/try", ovpnAdmin.LastSyncTimeHandler)
	http.HandleFunc("/api/sync/last/successful", ovpnAdmin.LastSuccessfulSyncTimeHandler)
	http.HandleFunc(backend.DownloadCertsApiUrl, ovpnAdmin.DownloadCertsHandler)
	http.HandleFunc(backend.DownloadCcdApiUrl, ovpnAdmin.DownloadCcdHandler)

	http.Handle(*backend.MetricsPath, promhttp.HandlerFor(ovpnAdmin.PromRegistry, promhttp.HandlerOpts{}))
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "pong")
	})

	log.Printf("Bind: http://%s:%s", *backend.ListenHost, *backend.ListenPort)
	log.Fatal(http.ListenAndServe(*backend.ListenHost+":"+*backend.ListenPort, nil))
}

func CacheControlWrapper(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=2592000") // 30 days
		h.ServeHTTP(w, r)
	})
}

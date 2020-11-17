package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"gopkg.in/alecthomas/kingpin.v2"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"text/template"
	"time"
)

const (
	usernameRegexp    = `^([a-zA-Z0-9_.-])+$`
	downloadCertsApiUrl = "/api/data/certs/download"
	downloadCcdApiUrl = "/api/data/ccd/download"
	certsArchiveFileName = "certs.tar.gz"
	ccdArchiveFileName = "ccd.tar.gz"
)

var (
	listenHost      		= kingpin.Flag("listen.host","host for openvpn-admin").Default("0.0.0.0").String()
	listenPort      		= kingpin.Flag("listen.port","port for openvpn-admin").Default("8080").String()
    serverRole              = kingpin.Flag("role","server role master or slave").Default("master").HintOptions("master", "slave").String()
	masterHost              = kingpin.Flag("master.host","Url for master server").Default("http://127.0.0.1").String()
	masterBasicAuthUser		= kingpin.Flag("master.basic-auth.user","user for basic auth on master server url").Default("").String()
	masterBasicAuthPassword = kingpin.Flag("master.basic-auth.password","password for basic auth on master server url").Default("").String()
	masterSyncFrequency     = kingpin.Flag("master.sync-frequency", "master host data sync frequency in seconds.").Default("600").Int()
	masterSyncToken         = kingpin.Flag("master.sync-token", "master host data sync security token").Required().String()
	openvpnServer      		= kingpin.Flag("ovpn.host","host for openvpn server").Default("127.0.0.1:7777").PlaceHolder("HOST:PORT").Strings()
	openvpnNetwork          = kingpin.Flag("ovpn.network","network for openvpn server").Default("172.16.100.0/24").String()
	mgmtListenHost          = kingpin.Flag("mgmt.host","host for openvpn server mgmt interface").Default("127.0.0.1").String()
	mgmtListenPort          = kingpin.Flag("mgmt.port","port for openvpn server mgmt interface").Default("8989").String()
	easyrsaDirPath     		= kingpin.Flag("easyrsa.path", "path to easyrsa dir").Default("/mnt/easyrsa").String()
	indexTxtPath    		= kingpin.Flag("easyrsa.index-path", "path to easyrsa index file.").Default("/mnt/easyrsa/pki/index.txt").String()
	ccdDir          		= kingpin.Flag("ccd.path", "path to client-config-dir").Default("/mnt/ccd").String()
	staticPath      		= kingpin.Flag("static.path", "path to static dir").Default("./static").String()
	debug           		= kingpin.Flag("debug", "Enable debug mode.").Default("false").Bool()

	certsArchivePath        = "/tmp/" + certsArchiveFileName
	ccdArchivePath          = "/tmp/" + ccdArchiveFileName
	lastSyncTime 		    = ""
	masterHostBsicAuth      = false
)

type OpenvpnServer struct {
	Host string
	Port  string
}

type openvpnClientConfig struct {
	Hosts []OpenvpnServer
	CA   string
	Cert string
	Key  string
	TLS  string
}

type OpenvpnClient struct {
	Identity            string      `json:"Identity"`
	AccountStatus       string      `json:"AccountStatus"`
    ExpirationDate      string      `json:"ExpirationDate"`
    RevocationDate      string      `json:"RevocationDate"`
	ConnectionStatus    string      `json:"ConnectionStatus"`
}

type ccdRoute struct {
	Address         string      `json:"Address"`
	Mask            string      `json:"Mask"`
	Description     string      `json:"Description"`
}

type Ccd struct {
    User            string      `json:"User"`
    ClientAddress   string      `json:"ClientAddress"`
	CustomRoutes    []ccdRoute  `json:"CustomRoutes"`
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
	CommonName             string
	RealAddress            string
	BytesReceived          string
	BytesSent              string
	ConnectedSince         string
	VirtualAddress         string
	LastRef                string
	ConnectedSinceFormated string
	LastRefFormated        string
}


func userListHandler(w http.ResponseWriter, r *http.Request) {
	usersList, _ := json.Marshal(usersList())
	fmt.Fprintf(w, "%s", usersList)
}

func userCreateHandler(w http.ResponseWriter, r *http.Request) {
	if *serverRole == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	r.ParseForm()
	userCreated, userCreateStatus := userCreate(r.FormValue("username"))

    if userCreated {
        w.WriteHeader(http.StatusOK)
        fmt.Fprintf(w, userCreateStatus)
        return
    } else {
	    http.Error(w, userCreateStatus, http.StatusUnprocessableEntity)
    }
}

func userRevokeHandler(w http.ResponseWriter, r *http.Request) {
	if *serverRole == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	r.ParseForm()
	fmt.Fprintf(w, "%s", userRevoke(r.FormValue("username")))
}

func userUnrevokeHandler(w http.ResponseWriter, r *http.Request) {
	if *serverRole == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}

	r.ParseForm()
	fmt.Fprintf(w, "%s", userUnrevoke(r.FormValue("username")))
}

func userShowConfigHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	fmt.Fprintf(w, "%s", renderClientConfig(r.FormValue("username")))
}

func userDisconnectHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
// 	fmt.Fprintf(w, "%s", userDisconnect(r.FormValue("username")))
	fmt.Fprintf(w, "%s", r.FormValue("username"))
}

func userShowCcdHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	ccd, _ := json.Marshal(getCcd(r.FormValue("username")))
	fmt.Fprintf(w, "%s", ccd)
}

func userApplyCcdHandler(w http.ResponseWriter, r *http.Request) {
	if *serverRole == "slave" {
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

    ccdApplied, applyStatus := modifyCcd(ccd)

    if ccdApplied {
        w.WriteHeader(http.StatusOK)
        fmt.Fprintf(w, applyStatus)
        return
    } else {
	    http.Error(w, applyStatus, http.StatusUnprocessableEntity)
    }
}

func serverRoleHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `{"status":"ok", "serverRole": "%s" }`, *serverRole)
}

func lastSyncTimeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, lastSyncTime)
}

func downloadCertsHandler(w http.ResponseWriter, r *http.Request) {
	if *serverRole == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	r.ParseForm()
	token := r.Form.Get("token")

	if token != *masterSyncToken {
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return
	}

	archiveCerts()
	w.Header().Set("Content-Disposition", "attachment; filename=" + certsArchiveFileName)
	http.ServeFile(w,r, certsArchivePath)
}

func downloadCddHandler(w http.ResponseWriter, r *http.Request) {
	if *serverRole == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	r.ParseForm()
	token := r.Form.Get("token")

	if token != *masterSyncToken {
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return
	}

	archiveCcd()
	w.Header().Set("Content-Disposition", "attachment; filename=" + ccdArchiveFileName)
	http.ServeFile(w,r, ccdArchivePath)
}

func main() {
    kingpin.Parse()

	if *masterBasicAuthPassword != "" && *masterBasicAuthUser != "" {
		masterHostBsicAuth = true
	}

	fmt.Println("Bind: http://" + *listenHost + ":" + *listenPort)

	if *serverRole == "slave" {
		syncDataFromMaster()
	    go syncWithMaster()
	}

	fs := CacheControlWrapper(http.FileServer(http.Dir(*staticPath)))

	http.Handle("/", fs)
	http.HandleFunc("/api/server/role", serverRoleHandler)
	http.HandleFunc("/api/users/list", userListHandler)
	http.HandleFunc("/api/user/create", userCreateHandler)
	http.HandleFunc("/api/user/revoke", userRevokeHandler)
	http.HandleFunc("/api/user/unrevoke", userUnrevokeHandler)
	http.HandleFunc("/api/user/config/show", userShowConfigHandler)
	http.HandleFunc("/api/user/disconnect", userDisconnectHandler)
	http.HandleFunc("/api/user/ccd", userShowCcdHandler)
	http.HandleFunc("/api/user/ccd/apply", userApplyCcdHandler)

	http.HandleFunc("/api/sync/last", lastSyncTimeHandler)
	http.HandleFunc(downloadCertsApiUrl, downloadCertsHandler)
	http.HandleFunc(downloadCcdApiUrl, downloadCddHandler)

	log.Fatal(http.ListenAndServe(*listenHost + ":" + *listenPort, nil))
}

func CacheControlWrapper(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=2592000") // 30 days
		h.ServeHTTP(w, r)
	})
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

func renderClientConfig(username string) string {
	if checkUserExist(username) {
		var hosts []OpenvpnServer

		for _, server := range *openvpnServer {
			parts := strings.SplitN(server, ":",2)
			hosts = append(hosts, OpenvpnServer{Host: parts[0], Port: parts[1]})
		}

		conf := openvpnClientConfig{}
		conf.Hosts = hosts
		conf.CA = fRead(*easyrsaDirPath + "/pki/ca.crt")
		conf.Cert = fRead(*easyrsaDirPath + "/pki/issued/" + username + ".crt")
		conf.Key = fRead(*easyrsaDirPath + "/pki/private/" + username + ".key")
		conf.TLS = fRead(*easyrsaDirPath + "/pki/ta.key")

		t, _ := template.ParseFiles("client.conf.tpl")
		var tmp bytes.Buffer
		t.Execute(&tmp, conf)

		hosts = nil

		fmt.Printf("%+v\n", tmp.String())
		return (fmt.Sprintf("%+v\n", tmp.String()))
	}
	fmt.Printf("User \"%s\" not found", username)
	return fmt.Sprintf("User \"%s\" not found", username)
}

func parseCcd(username string) Ccd {
	ccd := Ccd{}
	ccd.User = username
	ccd.ClientAddress = "dynamic"
	ccd.CustomRoutes = []ccdRoute{}

	txtLinesArray := strings.Split(fRead(*ccdDir + "/" + username), "\n")

	for _, v := range txtLinesArray {
		str := strings.Fields(v)
		if len(str) > 0 {
			switch {
			case strings.HasPrefix(str[0], "ifconfig-push"):
			    ccd.ClientAddress = str[1]
			case strings.HasPrefix(str[0], "push"):
				ccd.CustomRoutes =  append(ccd.CustomRoutes, ccdRoute{Address: strings.Trim(str[2], "\""), Mask: strings.Trim(str[3], "\""), Description: strings.Trim(strings.Join(str[4:], ""), "#")})
			}
		}
	}

	return ccd
}

func modifyCcd(ccd Ccd) (bool, string) {
	ccdErr := "something goes wrong"

    if fCreate(*ccdDir + "/" + ccd.User) {
        ccdValid, ccdErr := validateCcd(ccd)
        if ccdErr != "" {
		    return false, ccdErr
	    }

        if ccdValid {
            t, _ := template.ParseFiles("ccd.tpl")
            var tmp bytes.Buffer
            tplErr := t.Execute(&tmp, ccd)
			if tplErr != nil {
				log.Println(tplErr)
			}
            fWrite(*ccdDir + "/" + ccd.User, tmp.String())
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
                log.Printf("ERROR: Modify ccd for user %s: %s", ccd.User, ccdErr)
            }
            return false, ccdErr
	    }

        if net.ParseIP(ccd.ClientAddress) == nil {
            ccdErr = fmt.Sprintf("ClientAddress \"%s\" not a valid IP address", ccd.ClientAddress)
            if *debug {
                log.Printf("ERROR: Modify ccd for user %s: %s",  ccd.User, ccdErr)
            }
            return false, ccdErr
        }

        if ! ovpnNet.Contains(net.ParseIP(ccd.ClientAddress)) {
            ccdErr = fmt.Sprintf("ClientAddress \"%s\" not belongs to openvpn server network", ccd.ClientAddress)
            if *debug {
                log.Printf("ERROR: Modify ccd for user %s: %s", ccd.User, ccdErr)
            }
            return false, ccdErr
        }
    }

    for _, route := range ccd.CustomRoutes {
        if net.ParseIP(route.Address) == nil {
            ccdErr = fmt.Sprintf("CustomRoute.Address \"%s\" must be a valid IP address", route.Address)
            if *debug {
                log.Printf("ERROR: Modify ccd for user %s: %s", ccd.User, ccdErr)
            }
            return false, ccdErr
        }

        if net.ParseIP(route.Mask) == nil {
            ccdErr = fmt.Sprintf("CustomRoute.Mask \"%s\" must be a valid IP address", route.Mask)
            if *debug {
                log.Printf("ERROR: Modify ccd for user %s: %s", ccd.User, ccdErr)
            }
            return false, ccdErr
        }
    }

	return true, ccdErr
}

func getCcd(username string) Ccd {
	ccd := Ccd{}
	ccd.User = username
	ccd.ClientAddress = "dynamic"
	ccd.CustomRoutes = []ccdRoute{}

    if fCreate(*ccdDir + "/" + username) {
        ccd = parseCcd(username)
    }
    return ccd
}

func checkStaticAddressIsFree(staticAddress string, username string) bool {
    o := runBash(fmt.Sprintf("grep -rl %s %s | grep -vx %s/%s | wc -l", staticAddress, *ccdDir, *ccdDir, username))

    if strings.TrimSpace(o) == "0" {
        return true
    }
    return false
}

func validateUsername(username string) bool {
	var validUsername = regexp.MustCompile(usernameRegexp)
	return validUsername.MatchString(username)
}

func checkUserExist(username string) bool {
	for _, u := range indexTxtParser(fRead(*indexTxtPath)) {
		if u.DistinguishedName == ("/CN=" + username) {
			return true
		}
	}
	return false
}

func usersList() []OpenvpnClient {
	var users []OpenvpnClient
	activeClients := mgmtGetActiveClients()

	for _, line := range indexTxtParser(fRead(*indexTxtPath)) {
	    if line.Identity != "server" {
	        ovpnClient := OpenvpnClient{Identity: line.Identity, ExpirationDate: indexTxtDateToHumanReadable(line.ExpirationDate)}
            switch {
                case line.Flag == "V":
                    ovpnClient.AccountStatus = "Active"
                case line.Flag == "R":
                    ovpnClient.AccountStatus = "Revoked"
                    ovpnClient.RevocationDate = indexTxtDateToHumanReadable(line.RevocationDate)
                case line.Flag == "E":
                    ovpnClient.AccountStatus = "Expired"
            }
            if isUserConnected(line.Identity, activeClients) {
                ovpnClient.ConnectionStatus = "Connected"
            }
            users = append(users, ovpnClient)
        }
	}
	return users
}

func userCreate(username string) (bool, string) {
    ucErr := ""
    // TODO: add password for user cert . priority=low
	if validateUsername(username) == false {
		ucErr = fmt.Sprintf("Username \"%s\" incorrect, you can use only %s\n", username, usernameRegexp)
        if *debug {
            log.Printf("ERROR: userCreate: %s", ucErr)
        }
		return false, ucErr
	}
	if checkUserExist(username) {
		ucErr = fmt.Sprintf("User \"%s\" already exists\n", username)
        if *debug {
            log.Printf("ERROR: userCreate: %s", ucErr)
        }
		return false, ucErr
	}
	o := runBash(fmt.Sprintf("date +%%Y-%%m-%%d\\ %%H:%%M:%%S && cd %s && easyrsa build-client-full %s nopass", *easyrsaDirPath, username))
	fmt.Println(o)
	return true, fmt.Sprintf("User \"%s\" created", username)
}

func userRevoke(username string) string {
	if checkUserExist(username) {
		// check certificate valid flag 'V'
		o := runBash(fmt.Sprintf("date +%%Y-%%m-%%d\\ %%H:%%M:%%S && cd %s && echo yes | easyrsa revoke %s && easyrsa gen-crl", *easyrsaDirPath, username))
		crlFix()
		return fmt.Sprintln(o)
	}
	fmt.Printf("User \"%s\" not found", username)
	return fmt.Sprintf("User \"%s\" not found", username)
}

func userUnrevoke(username string) string {
	if checkUserExist(username) {
		// check certificate revoked flag 'R'
		usersFromIndexTxt := indexTxtParser(fRead(*indexTxtPath))
		for i := range usersFromIndexTxt {
			if usersFromIndexTxt[i].DistinguishedName == ("/CN=" + username) {
			    if usersFromIndexTxt[i].Flag == "R" {
                    usersFromIndexTxt[i].Flag = "V"
                    usersFromIndexTxt[i].RevocationDate = ""
                    o := runBash(fmt.Sprintf("cd %s && cp pki/revoked/certs_by_serial/%s.crt pki/issued/%s.crt", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber, username))
                    fmt.Println(o)
                    o = runBash(fmt.Sprintf("cd %s && cp pki/revoked/certs_by_serial/%s.crt pki/certs_by_serial/%s.pem", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber, usersFromIndexTxt[i].SerialNumber))
                    fmt.Println(o)
                    o = runBash(fmt.Sprintf("cd %s && cp pki/revoked/private_by_serial/%s.key pki/private/%s.key", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber, username))
                    fmt.Println(o)
                    o = runBash(fmt.Sprintf("cd %s && cp pki/revoked/reqs_by_serial/%s.req pki/reqs/%s.req", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber, username))
                    fmt.Println(o)
                    fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
                    fmt.Print(renderIndexTxt(usersFromIndexTxt))
                    o = runBash(fmt.Sprintf("cd %s && easyrsa gen-crl", *easyrsaDirPath))
                    fmt.Println(o)
                    crlFix()
                    break
                }
			}
		}
		fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
		fmt.Print(renderIndexTxt(usersFromIndexTxt))
		crlFix()
		return fmt.Sprintf("{\"msg\":\"User %s successfully unrevoked\"}", username)
	}
	return fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
}

// TODO: add ability to change password for user cert . priority=low
func userChangePassword(username string, newPassword string) bool {

    return false
}

func ovpnMgmtRead(conn net.Conn) string {
	buf := make([]byte, 32768)
	bufLen, _ := conn.Read(buf)
	s := string(buf[:bufLen])
	return s
}

func mgmtConnectedUsersParser(text string) []clientStatus {
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
			u = append(u, clientStatus{CommonName: user[0], RealAddress: user[1], BytesReceived: user[2], BytesSent: user[3], ConnectedSince: user[4]})
		}
		if isRouteTable {
			user := strings.Split(txt, ",")
			for i := range u {
				if u[i].CommonName == user[1] {
					u[i].VirtualAddress = user[0]
					u[i].LastRef = user[3]
					break
				}
			}
		}
	}
	return u
}

func mgmtKillUserConnection(username string) {
	conn, err := net.Dial("tcp", *mgmtListenHost+":"+*mgmtListenPort)
	if err != nil {
		log.Println("ERROR: openvpn mgmt interface is not reachable")
		return
	}
	ovpnMgmtRead(conn) // read welcome message
	conn.Write([]byte(fmt.Sprintf("kill %s\n", username)))
	fmt.Printf("%v", ovpnMgmtRead(conn))
	conn.Close()
}

func mgmtGetActiveClients() []clientStatus {
	conn, err := net.Dial("tcp", *mgmtListenHost+":"+*mgmtListenPort)
	if err != nil {
		log.Println("ERROR: openvpn mgmt interface is not reachable")
		return []clientStatus{}
	}
	ovpnMgmtRead(conn) // read welcome message
	conn.Write([]byte("status\n"))
	activeClients := mgmtConnectedUsersParser(ovpnMgmtRead(conn))
	conn.Close()
	return activeClients
}

func isUserConnected(username string, connectedUsers []clientStatus) bool {
    for _, connectedUser := range connectedUsers {
        if connectedUser.CommonName == username {
            return true
        }
    }
    return false
}

func downloadCerts() bool {
	if fExist(certsArchivePath) {
		fDelete(certsArchivePath)
	}
    err := fDownload(certsArchivePath, *masterHost + downloadCertsApiUrl + "?token=" + *masterSyncToken, masterHostBsicAuth)
    if err != nil {
		log.Fatal(err)
		return false
	}

	return true
}

func downloadCcd() bool {
	if fExist(ccdArchivePath) {
		fDelete(ccdArchivePath)
	}

	err := fDownload(ccdArchivePath, *masterHost + downloadCcdApiUrl + "?token=" + *masterSyncToken, masterHostBsicAuth)
	if err != nil {
		log.Fatal(err)
		return false
	}

	return true
}

func archiveCerts() {
	o := runBash(fmt.Sprintf("cd %s && tar -czf %s *", *easyrsaDirPath + "/pki", certsArchivePath ))
	fmt.Println(o)
}

func archiveCcd() {
	o := runBash(fmt.Sprintf("cd %s && tar -czf %s *", *ccdDir, ccdArchivePath ))
	fmt.Println(o)
}

func unArchiveCerts() {
	runBash(fmt.Sprintf("mkdir -p %s", *easyrsaDirPath + "/pki"))
	o := runBash(fmt.Sprintf("cd %s && tar -xzf %s", *easyrsaDirPath + "/pki", certsArchivePath ))
	fmt.Println(o)
}

func unArchiveCcd() {
	runBash(fmt.Sprintf("mkdir -p %s", *ccdDir))
	o := runBash(fmt.Sprintf("cd %s && tar -xzf %s", *ccdDir, ccdArchivePath ))
	fmt.Println(o)
}

func syncDataFromMaster() {
	downloadCerts()
	downloadCcd()

	unArchiveCerts()
	unArchiveCcd()

	lastSyncTime = time.Now().Format("2006-01-02 15:04:05")
}

func syncWithMaster() {
    for {
		time.Sleep(time.Duration(*masterSyncFrequency) * time.Second)
		syncDataFromMaster()
    }
}

// https://community.openvpn.net/openvpn/ticket/623
func crlFix() {
	os.Chmod(*easyrsaDirPath + "/pki", 0755)
	err := os.Chmod(*easyrsaDirPath + "/pki/crl.pem", 0640)
	if err != nil {
		log.Println(err)
	}
}
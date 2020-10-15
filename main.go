package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"text/template"
	// "reflect"
	"bufio"
	"net"
	// "io"
	// "encoding/binary"
	"encoding/json"
	"net/http"
    "gopkg.in/alecthomas/kingpin.v2"
)

var (
    listenHost      = kingpin.Flag("listen.host","host for openvpn-admin").Default("127.0.0.1").String()
	listenPort      = kingpin.Flag("listen.port","port for openvpn-admin").Default("8080").String()
    easyrsaPath     = kingpin.Flag("easyrsa.path", "path to easyrsa dir").Default("/etc/openvpn/easyrsa").String()
    indexTxtPath    = kingpin.Flag("easyrsa.index-path", "path to easyrsa index file.").Default("/etc/openvpn/easyrsa/pki/index.txt").String()
    ccdCustom       = kingpin.Flag("ccd.custom", "enable or disable custom routes").Default("false").Bool()
    ccdDir          = kingpin.Flag("ccd.path", "path to client-config-dir").Default("/etc/openvpn/ccd").String()
    staticPath      = kingpin.Flag("static.path", "path to static dir").Default("./static").String()
)

const (
	usernameRegexp    = `^([a-zA-Z0-9_.-])+$`
	openvpnServerHost = "127.0.0.1"
	openvpnServerPort = "7777"
	mgmtListenHost    = "127.0.0.1"
	mgmtListenPort    = "7788"
)

type openvpnClientConfig struct {
	Host string
	Port string
	CA   string
	Cert string
	Key  string
	TLS  string
}

type ccdLine struct {
	addr string `json:"addr"`
	mask string `json:"mask"`
	desc string `json:"desc"`
}

type ccdFile struct {
	lines []ccdLine
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
	userList, _ := json.Marshal(indexTxtParser(fRead(*indexTxtPath)))
	fmt.Fprintf(w, "%s", userList)
}

func userCreateHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	fmt.Fprintf(w, "%s", userCreate(r.FormValue("username")))
}

func userRevokeHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	fmt.Fprintf(w, "%s", userRevoke(r.FormValue("username")))
}

func userUnrevokeHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	fmt.Fprintf(w, "%s", userUnrevoke(r.FormValue("username")))
}

func userShowConfigHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	fmt.Printf("username: %v\n%s\n", r.PostForm, r.FormValue("username"))
	fmt.Fprintf(w, "%s", renderClientConfig(r.FormValue("username")))
}

func userShowCcdHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	fmt.Printf("username: %v\n%s\n", r.PostForm, r.FormValue("username"))
	fmt.Fprintf(w, "%s", renderCcdConfig(r.FormValue("username")))
}

func userApplyCcdHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	fmt.Printf("username: %v\n%s\n", r.PostForm, r.FormValue("username"))
	fmt.Fprintf(w, "%s", ccdFileModify(r.FormValue("username"),ccdFileParser(r.FormValue("ccd"))))
}

func main() {
    kingpin.Parse()

	fmt.Println("Bind: http://" + *listenHost + ":" + *listenPort)

	fs := http.FileServer(http.Dir(*staticPath))

	http.Handle("/", fs)
	http.HandleFunc("/api/users/list", userListHandler)
	http.HandleFunc("/api/user/create", userCreateHandler)
	http.HandleFunc("/api/user/revoke", userRevokeHandler)
	http.HandleFunc("/api/user/unrevoke", userUnrevokeHandler)
	http.HandleFunc("/api/user/showconfig", userShowConfigHandler)
	http.HandleFunc("/api/user/ccd/list", userShowCcdHandler)
	http.HandleFunc("/api/user/ccd/apply", userApplyCcdHandler)

	log.Fatal(http.ListenAndServe(*listenHost + ":" + *listenPort, nil))
}

func fRead(path string) string {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	return string(content)
}

func fWrite(path, content string) {
	err := ioutil.WriteFile(path, []byte(content), 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func indexTxtParser(txt string) []indexTxtLine {
	indexTxt := []indexTxtLine{}

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
			// if line.distinguishedName != "/CN=server" {
			// fmt.Printf("%s\t%s\t\t%s\t%s\t%s\n", line.flag, line.expirationDate, line.serialNumber, line.filename, line.distinguishedName)
			indexTxt += fmt.Sprintf("%s\t%s\t\t%s\t%s\t%s\n", line.Flag, line.ExpirationDate, line.SerialNumber, line.Filename, line.DistinguishedName)
			// }
		case line.Flag == "R":
			// if line.distinguishedName != "/CN=server" {
			// fmt.Printf("%s\t%s\t%s\t%s\t%s\t%s\n", line.flag, line.expirationDate, line.revocationDate, line.serialNumber, line.filename, line.distinguishedName)
			indexTxt += fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\n", line.Flag, line.ExpirationDate, line.RevocationDate, line.SerialNumber, line.Filename, line.DistinguishedName)
			// }
			// case line.flag == "E":
		}
	}
	return (indexTxt)
}

func renderClientConfig(username string) string {
	if checkUserExist(username) {
		conf := openvpnClientConfig{}
		conf.Host = openvpnServerHost
		conf.Port = openvpnServerPort
		conf.CA = fRead(*easyrsaPath + "/pki/ca.crt")
		conf.Cert = fRead(*easyrsaPath + "/pki/issued/" + username + ".crt")
		conf.Key = fRead(*easyrsaPath + "/pki/private/" + username + ".key")
		conf.TLS = fRead(*easyrsaPath + "/pki/ta.key")
		t, _ := template.ParseFiles("client.conf.tpl")
		var tmp bytes.Buffer
		t.Execute(&tmp, conf)
		// fmt.Printf("%+v\n", err)
		fmt.Printf("%+v\n", tmp.String())
		return (fmt.Sprintf("%+v\n", tmp.String()))
	}
	fmt.Printf("User \"%s\" not found", username)
	return (fmt.Sprintf("User \"%s\" not found", username))
}

func ccdFileParser(txt string) ccdFile {
	ccdFile := ccdFile{}

	txtLinesArray := strings.Split(txt, "\n")

	for _, v := range txtLinesArray {
		str := strings.Fields(v)
		if len(str) > 0 {
			switch {
			case strings.HasPrefix(str[0], "ifconfig-push"):
			    ccdFile.lines = append(ccdFile.lines, ccdLine{addr: str[2], mask: str[3], desc: "Client Address"})
			case strings.HasPrefix(str[0], "push"):
				ccdFile.lines = append(ccdFile.lines, ccdLine{addr: str[2], mask: str[3], desc: strings.Join(str[4:], "")})
			}
		}
	}

	return ccdFile
}


func renderCcdConfig(username string) string {
    if checkCcdExist(username) {
        ccdFileParser(fRead(*ccdDir + "/" + username))
    }

	fmt.Printf("ccd for user \"%s\" not found", username)
	return (fmt.Sprintf("ccd for user \"%s\" not found", username))
}


func ccdFileModify(username string, ccdFile ccdFile) bool {
    if checkCcdExist(username) {
    }
	return true
}

// https://community.openvpn.net/openvpn/ticket/623
func crlFix() {
	os.Chmod(*easyrsaPath + "/pki", 0755)
	err := os.Chmod(*easyrsaPath + "/pki/crl.pem", 0640)
	if err != nil {
		log.Println(err)
	}
}

func runBash(script string) string {
	fmt.Println(script)
	cmd := exec.Command("bash", "-c", script)
	stdout, err := cmd.CombinedOutput()
	if err != nil {
		return (fmt.Sprint(err) + " : " + string(stdout))
	}
	return (string(stdout))
}

func validateUsername(username string) bool {
	var validUsername = regexp.MustCompile(usernameRegexp)
	return (validUsername.MatchString(username))
}

func checkUserExist(username string) bool {
	for _, u := range indexTxtParser(fRead(*indexTxtPath)) {
		if u.DistinguishedName == ("/CN=" + username) {
			return (true)
		}
	}
	return (false)
}

func checkCcdExist(username string) bool {
    if *ccdCustom {
        if _, err := os.Stat(*ccdDir + "/" + username); err == nil {
            return (true)
        } else if os.IsNotExist(err) {
            fmt.Printf("ccd for user \"%s\" not found", username)
            return (false)
        } else {
            fmt.Printf("Something goes wrong during checking ccd for user \"%s\"", username)
            fmt.Printf("err: %s", err)
            return (false)
        }
    }

	return (false)
}

func usersList() []string {
	users := []string{}
	for _, line := range indexTxtParser(fRead(*indexTxtPath)) {
		users = append(users, line.Identity)
	}
	return (users)
}

func userCreate(username string) string {
	if validateUsername(username) == false {
		fmt.Printf("Username \"%s\" incorrect, you can use only %s\n", username, usernameRegexp)
		return (fmt.Sprintf("Username \"%s\" incorrect, you can use only %s\n", username, usernameRegexp))
	}
	if checkUserExist(username) {
		fmt.Printf("User \"%s\" already exists\n", username)
		return (fmt.Sprintf("User \"%s\" already exists\n", username))
	}
	o := runBash(fmt.Sprintf("date +%%Y-%%m-%%d\\ %%H:%%M:%%S && cd %s && ./easyrsa build-client-full %s nopass", *easyrsaPath, username))
	fmt.Println(o)
	return ("")
}

func userRevoke(username string) string {
	if checkUserExist(username) {
		// check certificate valid flag 'V'
		o := runBash(fmt.Sprintf("date +%%Y-%%m-%%d\\ %%H:%%M:%%S && cd %s && echo yes | ./easyrsa revoke %s && ./easyrsa gen-crl", *easyrsaPath, username))
		crlFix()
		return (fmt.Sprintln(o))
	}
	fmt.Printf("User \"%s\" not found", username)
	return (fmt.Sprintf("User \"%s\" not found", username))
}

func userUnrevoke(username string) string {
	if checkUserExist(username) {
		// check certificate revoked flag 'R'
		usersFromIndexTxt := indexTxtParser(fRead(*indexTxtPath))
		for i := range usersFromIndexTxt {
			if usersFromIndexTxt[i].DistinguishedName == ("/CN=" + username) {
				usersFromIndexTxt[i].Flag = "V"
				usersFromIndexTxt[i].RevocationDate = ""
				break
			}
		}
		fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
		fmt.Print(renderIndexTxt(usersFromIndexTxt))
		crlFix()
		return (fmt.Sprintf("{\"msg\":\"User %s successfully unrevoked\"}", username))
	}
	return (fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username))
}

func ovpnMgmtRead(conn net.Conn) string {
	buf := make([]byte, 32768)
	len, _ := conn.Read(buf)
	s := string(buf[:len])
	return (s)
}

func mgmtConnectedUsersParser(text string) []clientStatus {
	u := []clientStatus{}
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
	return (u)
}

func mgmtKillUserConnection(username string) {
	conn, _ := net.Dial("tcp", mgmtListenHost+":"+mgmtListenPort)
	ovpnMgmtRead(conn) // read welcome message
	conn.Write([]byte(fmt.Sprintf("kill %s\n", username)))
	fmt.Printf("%v", ovpnMgmtRead(conn))
	conn.Close()
}

func mgmtGetActiveClients() []clientStatus {
	conn, _ := net.Dial("tcp", mgmtListenHost+":"+mgmtListenPort)
	ovpnMgmtRead(conn) // read welcome message
	conn.Write([]byte("status\n"))
	activeClients := mgmtConnectedUsersParser(ovpnMgmtRead(conn))
	conn.Close()
	return (activeClients)
}

package backend

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	certsArchivePath = "/tmp/" + certsArchiveFileName
	ccdArchivePath   = "/tmp/" + ccdArchiveFileName
)

func validateCcd(ccd CCD) (bool, string) {

	ccdErr := ""

	if ccd.ClientAddress != "dynamic" {
		_, ovpnNet, err := net.ParseCIDR(*openvpnNetwork)
		if err != nil {
			log.Error(err)
		}

		if !checkStaticAddressIsFree(ccd.ClientAddress, ccd.User) {
			ccdErr = fmt.Sprintf("ClientAddress \"%s\" already assigned to another user", ccd.ClientAddress)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}

		if net.ParseIP(ccd.ClientAddress) == nil {
			ccdErr = fmt.Sprintf("ClientAddress \"%s\" not a valid IP address", ccd.ClientAddress)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}

		if !ovpnNet.Contains(net.ParseIP(ccd.ClientAddress)) {
			ccdErr = fmt.Sprintf("ClientAddress \"%s\" not belongs to openvpn server network", ccd.ClientAddress)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}
	}

	for _, route := range ccd.CustomRoutes {
		if net.ParseIP(route.Address) == nil {
			ccdErr = fmt.Sprintf("CustomRoute.Address \"%s\" must be a valid IP address", route.Address)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}

		if net.ParseIP(route.Mask) == nil {
			ccdErr = fmt.Sprintf("CustomRoute.Mask \"%s\" must be a valid IP address", route.Mask)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}
	}

	return true, ccdErr
}

func checkStaticAddressIsFree(staticAddress string, username string) bool {
	o := runBash(fmt.Sprintf("grep -rl ' %s ' %s | grep -vx %s/%s | wc -l", staticAddress, *CcdDir, *CcdDir, username))

	if strings.TrimSpace(o) == "0" {
		return true
	}
	return false
}

func validateUsername(username string) error {
	var validUsername = regexp.MustCompile(usernameRegexp)
	if validUsername.MatchString(username) {
		return nil
	} else {
		return errors.New(fmt.Sprintf("Username can only contains %s", usernameRegexp))
	}
}

func validatePassword(password string) error {
	if utf8.RuneCountInString(password) < passwordMinLength {
		return errors.New(fmt.Sprintf("Password too short, password length must be greater or equal %d", passwordMinLength))
	} else {
		return nil
	}
}

func checkUserExist(username string) bool {
	for _, u := range IndexTxtParser(fRead(*IndexTxtPath)) {
		if u.DistinguishedName == ("/CN=" + username) {
			return true
		}
	}
	return false
}

func isUserConnected(username string, connectedUsers []ClientStatus) (bool, []string) {
	var connections []string
	var connected = false

	for _, connectedUser := range connectedUsers {
		if connectedUser.CommonName == username {
			connected = true
			connections = append(connections, connectedUser.ConnectedTo)
		}
	}
	return connected, connections
}

func archiveCerts() {
	err := createArchiveFromDir(*EasyrsaDirPath+"/pki", certsArchivePath)
	if err != nil {
		log.Warnf("archiveCerts(): %s", err)
	}
}

func archiveCcd() {
	err := createArchiveFromDir(*CcdDir, ccdArchivePath)
	if err != nil {
		log.Warnf("archiveCcd(): %s", err)
	}
}

func unArchiveCerts() {
	if err := os.MkdirAll(*EasyrsaDirPath+"/pki", 0755); err != nil {
		log.Warnf("unArchiveCerts(): error creating pki dir: %s", err)
	}

	err := extractFromArchive(certsArchivePath, *EasyrsaDirPath+"/pki")
	if err != nil {
		log.Warnf("unArchiveCerts: extractFromArchive() %s", err)
	}
}

func unArchiveCcd() {
	if err := os.MkdirAll(*CcdDir, 0755); err != nil {
		log.Warnf("unArchiveCcd(): error creating ccd dir: %s", err)
	}

	err := extractFromArchive(ccdArchivePath, *CcdDir)
	if err != nil {
		log.Warnf("unArchiveCcd: extractFromArchive() %s", err)
	}
}

func getOvpnServerHostsFromKubeApi() ([]OpenvpnServer, error) {
	var hosts []OpenvpnServer
	var lbHost string

	config, err := rest.InClusterConfig()
	if err != nil {
		log.Errorf("%s", err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Errorf("%s", err.Error())
	}

	for _, serviceName := range *openvpnServiceName {
		service, err := clientset.CoreV1().Services(fRead(KubeNamespaceFilePath)).Get(context.TODO(), serviceName, metav1.GetOptions{})
		if err != nil {
			log.Error(err)
		}

		log.Tracef("service from kube api %v", service)
		log.Tracef("service.Status from kube api %v", service.Status)
		log.Tracef("service.Status.LoadBalancer from kube api %v", service.Status.LoadBalancer)

		lbIngress := service.Status.LoadBalancer.Ingress
		if len(lbIngress) > 0 {
			if lbIngress[0].Hostname != "" {
				lbHost = lbIngress[0].Hostname
			}

			if lbIngress[0].IP != "" {
				lbHost = lbIngress[0].IP
			}
		}

		hosts = append(hosts, OpenvpnServer{lbHost, strconv.Itoa(int(service.Spec.Ports[0].Port)), strings.ToLower(string(service.Spec.Ports[0].Protocol))})
	}

	if len(hosts) == 0 {
		return []OpenvpnServer{{Host: "kubernetes services not found"}}, err
	}

	return hosts, nil
}

func getOvpnCaCertExpireDate() time.Time {
	caCertPath := *EasyrsaDirPath + "/pki/ca.crt"
	caCert, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		log.Errorf("error read file %s: %s", caCertPath, err.Error())
	}

	certPem, _ := pem.Decode(caCert)
	certPemBytes := certPem.Bytes

	cert, err := x509.ParseCertificate(certPemBytes)
	if err != nil {
		log.Errorf("error parse certificate ca.crt: %s", err.Error())
		return time.Now()
	}

	return cert.NotAfter
}

// https://community.openvpn.net/openvpn/ticket/623
func crlFix() {
	err := os.Chmod(*EasyrsaDirPath+"/pki", 0755)
	if err != nil {
		log.Error(err)
	}
	err = os.Chmod(*EasyrsaDirPath+"/pki/crl.pem", 0644)
	if err != nil {
		log.Error(err)
	}
}

func parseDate(layout, datetime string) time.Time {
	t, err := time.Parse(layout, datetime)
	if err != nil {
		log.Errorln(err)
	}
	return t
}

func parseDateToString(layout, datetime, format string) string {
	return parseDate(layout, datetime).Format(format)
}

func parseDateToUnix(layout, datetime string) int64 {
	return parseDate(layout, datetime).Unix()
}

func runBash(script string) string {
	log.Debugln(script)
	cmd := exec.Command("bash", "-c", script)
	stdout, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprint(err) + " : " + string(stdout)
	}
	return string(stdout)
}

func fExist(path string) bool {
	var _, err = os.Stat(path)

	if os.IsNotExist(err) {
		return false
	} else if err != nil {
		log.Fatalf("fExist: %s", err)
		return false
	}

	return true
}

func fRead(path string) string {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		log.Warning(err)
		return ""
	}

	return string(content)
}

func fCreate(path string) error {
	var _, err = os.Stat(path)
	if os.IsNotExist(err) {
		var file, err = os.Create(path)
		if err != nil {
			log.Errorln(err)
			return err
		}
		defer file.Close()
	}
	return nil
}

func fWrite(path, content string) error {
	err := ioutil.WriteFile(path, []byte(content), 0644)
	if err != nil {
		log.Fatal(err)
	}
	return nil
}

func fDelete(path string) error {
	err := os.Remove(path)
	if err != nil {
		log.Fatal(err)
	}
	return nil
}

func fCopy(src, dst string) error {
	sfi, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !sfi.Mode().IsRegular() {
		// cannot copy non-regular files (e.g., directories, symlinks, devices, etc.)
		return fmt.Errorf("fCopy: non-regular source file %s (%q)", sfi.Name(), sfi.Mode().String())
	}
	dfi, err := os.Stat(dst)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else {
		if !(dfi.Mode().IsRegular()) {
			return fmt.Errorf("fCopy: non-regular destination file %s (%q)", dfi.Name(), dfi.Mode().String())
		}
		if os.SameFile(sfi, dfi) {
			return err
		}
	}
	if err = os.Link(src, dst); err == nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	err = out.Sync()
	return err
}

func fMove(src, dst string) error {
	err := fCopy(src, dst)
	if err != nil {
		log.Warn(err)
		return err
	}
	err = fDelete(src)
	if err != nil {
		log.Warn(err)
		return err
	}

	return nil
}

func fDownload(path, url string, basicAuth bool) error {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if basicAuth {
		req.SetBasicAuth(*MasterBasicAuthUser, *MasterBasicAuthPassword)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		log.Warnf("WARNING: Download file operation for url %s finished with status code %d\n", url, resp.StatusCode)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	err = fCreate(path)
	if err != nil {
		return err
	}
	err = fWrite(path, string(body))
	if err != nil {
		return err
	}

	return nil
}

func createArchiveFromDir(dir, path string) error {

	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Warn(err)
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		log.Warn(err)
	}

	out, err := os.Create(path)
	if err != nil {
		log.Errorf("Error writing archive %s: %s", path, err)
		return err
	}
	defer out.Close()
	gw := gzip.NewWriter(out)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Iterate over files and add them to the tar archive
	for _, filePath := range files {
		file, err := os.Open(filePath)
		if err != nil {
			log.Warnf("Error writing archive %s: %s", path, err)
			return err
		}

		// Get FileInfo about our file providing file size, mode, etc.
		info, err := file.Stat()
		if err != nil {
			file.Close()
			return err
		}

		// Create a tar Header from the FileInfo data
		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			file.Close()
			return err
		}

		header.Name = strings.Replace(filePath, dir+"/", "", 1)

		// Write file header to the tar archive
		err = tw.WriteHeader(header)
		if err != nil {
			file.Close()
			return err
		}

		// Copy file content to tar archive
		_, err = io.Copy(tw, file)
		if err != nil {
			file.Close()
			return err
		}
		file.Close()
	}

	return nil
}

func extractFromArchive(archive, path string) error {
	// Open the file which will be written into the archive
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write file header to the tar archive
	uncompressedStream, err := gzip.NewReader(file)
	if err != nil {
		log.Fatal("extractFromArchive(): NewReader failed")
	}

	tarReader := tar.NewReader(uncompressedStream)

	for true {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Fatalf("extractFromArchive: Next() failed: %s", err.Error())
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(path+"/"+header.Name, 0755); err != nil {
				log.Fatalf("extractFromArchive: Mkdir() failed: %s", err.Error())
			}
		case tar.TypeReg:
			outFile, err := os.Create(path + "/" + header.Name)
			if err != nil {
				log.Fatalf("extractFromArchive: Create() failed: %s", err.Error())
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				log.Fatalf("extractFromArchive: Copy() failed: %s", err.Error())
			}
			outFile.Close()

		default:
			log.Fatalf(
				"extractFromArchive: uknown type: %s in %s", header.Typeflag, header.Name)
		}
	}
	return nil
}

func randStr(strSize int, randType string) string {

	var dictionary string

	if randType == "alphanum" {
		dictionary = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	}

	if randType == "alpha" {
		dictionary = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	}

	if randType == "number" {
		dictionary = "0123456789"
	}

	var bytes = make([]byte, strSize)

	for k, v := range bytes {
		bytes[k] = dictionary[v%byte(len(dictionary))]
	}
	return string(bytes)
}

package backend

import (
	"bufio"
	"bytes"
	"encoding/base32"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"
	ou "github.com/pashcovich/openvpn-user/src"
	log "github.com/sirupsen/logrus"
)

func (oAdmin *OvpnAdmin) RegisterMetrics() {
	oAdmin.PromRegistry.MustRegister(OvpnServerCertExpire)
	oAdmin.PromRegistry.MustRegister(OvpnServerCaCertExpire)
	oAdmin.PromRegistry.MustRegister(OvpnClientsTotal)
	oAdmin.PromRegistry.MustRegister(OvpnClientsRevoked)
	oAdmin.PromRegistry.MustRegister(OvpnClientsConnected)
	oAdmin.PromRegistry.MustRegister(OvpnUniqClientsConnected)
	oAdmin.PromRegistry.MustRegister(OvpnClientsExpired)
	oAdmin.PromRegistry.MustRegister(OvpnClientCertificateExpire)
	oAdmin.PromRegistry.MustRegister(OvpnClientConnectionInfo)
	oAdmin.PromRegistry.MustRegister(OvpnClientConnectionFrom)
	oAdmin.PromRegistry.MustRegister(OvpnClientBytesReceived)
	oAdmin.PromRegistry.MustRegister(OvpnClientBytesSent)
}

func (oAdmin *OvpnAdmin) SetState() {
	oAdmin.activeClients = oAdmin.mgmtGetActiveClients()
	oAdmin.clients = oAdmin.usersList()

	OvpnServerCaCertExpire.Set(float64((getOvpnCaCertExpireDate().Unix() - time.Now().Unix()) / 3600 / 24))
}

func (oAdmin *OvpnAdmin) UpdateState() {
	for {
		time.Sleep(time.Duration(28) * time.Second)
		OvpnClientBytesSent.Reset()
		OvpnClientBytesReceived.Reset()
		OvpnClientConnectionFrom.Reset()
		OvpnClientConnectionInfo.Reset()
		OvpnClientCertificateExpire.Reset()
		go oAdmin.SetState()
	}
}

func IndexTxtParser(txt string) []indexTxtLine {
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

func (oAdmin *OvpnAdmin) getTemplate(name, tplName, path string) *template.Template {
	if path != "" {
		return template.Must(template.ParseFiles(path))
	} else {
		tpl, err := fs.ReadFile(oAdmin.Templates, name)
		if err != nil {
			log.Errorf("%s not found in templates box: %s", name, err)
			return nil
		}
		return template.Must(template.New(tplName).Parse(string(tpl)))
	}
}

//func (oAdmin *OvpnAdmin) getClientConfigTemplate() *template.Template {
//	if *clientConfigTemplatePath != "" {
//		return template.Must(template.ParseFiles(*clientConfigTemplatePath))
//	} else {
//		clientConfigFileTpl, ccdTplFileErr := fs.Glob(oAdmin.Templates, "client.conf.tpl")
//		log.Debug(clientConfigFileTpl)
//		if ccdTplFileErr != nil {
//			log.Errorf("clientConfigTpl not found in templates box")
//		}
//		log.Debug(len(clientConfigFileTpl))
//		if len(clientConfigFileTpl) == 1 {
//			clientConfigTpl, clientConfigTplErr := fs.ReadFile(oAdmin.Templates, clientConfigFileTpl[0])
//			if clientConfigTplErr != nil {
//				log.Errorf("clientConfigTpl not found in templates box")
//			}
//			log.Debug(len(clientConfigTpl))
//			return template.Must(template.New("ccd").Parse(string(clientConfigTpl)))
//		}
//		return nil
//	}
//}

func (oAdmin *OvpnAdmin) renderClientConfig(username string) string {
	if checkUserExist(username) {
		var hosts []OpenvpnServer

		for _, server := range *openvpnServer {
			parts := strings.SplitN(server, ":", 3)
			hosts = append(hosts, OpenvpnServer{Host: parts[0], Port: parts[1], Protocol: parts[2]})
		}

		if *openvpnServerBehindLB {
			var err error
			hosts, err = getOvpnServerHostsFromKubeApi()
			if err != nil {
				log.Error(err)
			}
		}

		conf := openvpnClientConfig{}
		conf.Hosts = hosts
		conf.CA = fRead(*EasyrsaDirPath + "/pki/ca.crt")
		conf.TLS = fRead(*EasyrsaDirPath + "/pki/ta.key")

		if *StorageBackend == "kubernetes.secrets" {
			conf.Cert, conf.Key = oAdmin.KubeClient.EasyrsaGetClientCert(username)
		} else {
			conf.Cert = fRead(*EasyrsaDirPath + "/pki/issued/" + username + ".crt")
			conf.Key = fRead(*EasyrsaDirPath + "/pki/private/" + username + ".key")
		}

		conf.PasswdAuth = oAdmin.ExtraAuth

		t := oAdmin.getTemplate("client.conf.tpl", "client-config", *clientConfigTemplatePath)

		var tmp bytes.Buffer
		err := t.Execute(&tmp, conf)
		if err != nil {
			log.Errorf("something goes wrong during rendering config for %s", username)
			log.Debugf("rendering config for %s failed with error %v", username, err)
		}

		hosts = nil

		log.Tracef("Rendered config for user %s: %+v", username, tmp.String())

		return fmt.Sprintf("%+v", tmp.String())
	}
	log.Warnf("user \"%s\" not found", username)
	return fmt.Sprintf("user \"%s\" not found", username)
}

//func (oAdmin *OvpnAdmin) getCcdTemplate() *template.Template {
//	if *ccdTemplatePath != "" {
//		return template.Must(template.ParseFiles(*ccdTemplatePath))
//	} else {
//		//ccdTpl, ccdTplErr := oAdmin.Templates.FindString("ccd.tpl")
//		ccdTplFile, ccdTplFileErr := fs.Glob(oAdmin.Templates, "ccd.tpl")
//		log.Debug(ccdTplFile)
//		if ccdTplFileErr != nil {
//			log.Errorf("ccdTpl not found in templates box")
//		}
//		log.Debug(len(ccdTplFile))
//
//		if len(ccdTplFile) == 1 {
//			ccdTpl, ccdTplErr := fs.ReadFile(oAdmin.Templates, ccdTplFile[0])
//			if ccdTplErr != nil {
//				log.Errorf("ccdTpl not found in templates box")
//			}
//			log.Debug(ccdTpl)
//			return template.Must(template.New("ccd").Parse(string(ccdTpl)))
//		}
//		log.Debug("returning nil")
//
//		return nil
//	}
//}

func (oAdmin *OvpnAdmin) parseCcd(username string) CCD {
	ccd := CCD{}
	ccd.User = username
	ccd.ClientAddress = "dynamic"
	ccd.CustomRoutes = []ccdRoute{}

	var txtLinesArray []string
	if *StorageBackend == "kubernetes.secrets" {
		txtLinesArray = strings.Split(oAdmin.KubeClient.SecretGetCcd(ccd.User), "\n")
	} else {
		if fExist(*CcdDir + "/" + username) {
			txtLinesArray = strings.Split(fRead(*CcdDir+"/"+username), "\n")
		}
	}

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

func (oAdmin *OvpnAdmin) modifyCcd(ccd CCD) (bool, string) {
	ccdValid, err := validateCcd(ccd)
	if err != "" {
		return false, err
	}

	if ccdValid {
		t := oAdmin.getTemplate("ccd.tpl", "ccd", *ccdTemplatePath)
		var tmp bytes.Buffer
		err := t.Execute(&tmp, ccd)
		if err != nil {
			log.Error(err)
		}
		if *StorageBackend == "kubernetes.secrets" {
			oAdmin.KubeClient.SecretUpdateCcd(ccd.User, tmp.Bytes())
		} else {
			err = fWrite(*CcdDir+"/"+ccd.User, tmp.String())
			if err != nil {
				log.Errorf("modifyCcd: fWrite(): %v", err)
			}
		}

		return true, "ccd updated successfully"
	}

	return false, "something goes wrong"
}

func (oAdmin *OvpnAdmin) getCcd(username string) CCD {
	ccd := CCD{}
	ccd.User = username
	ccd.ClientAddress = "dynamic"
	ccd.CustomRoutes = []ccdRoute{}

	ccd = oAdmin.parseCcd(username)

	return ccd
}

func (oAdmin *OvpnAdmin) usersList() []OpenvpnClient {
	var users []OpenvpnClient

	totalCerts := 0
	validCerts := 0
	revokedCerts := 0
	expiredCerts := 0
	connectedUniqUsers := 0
	totalActiveConnections := 0
	apochNow := time.Now().Unix()

	for _, line := range IndexTxtParser(fRead(*IndexTxtPath)) {
		if line.Identity != "server" && !strings.Contains(line.Identity, "REVOKED") {
			totalCerts += 1
			ovpnClient := OpenvpnClient{Identity: line.Identity, ExpirationDate: parseDateToString(indexTxtDateLayout, line.ExpirationDate, stringDateFormat)}
			switch {
			case line.Flag == "V":
				ovpnClient.AccountStatus = "Active"
				validCerts += 1
			case line.Flag == "R":
				ovpnClient.AccountStatus = "Revoked"
				ovpnClient.RevocationDate = parseDateToString(indexTxtDateLayout, line.RevocationDate, stringDateFormat)
				revokedCerts += 1
			case line.Flag == "E":
				ovpnClient.AccountStatus = "Expired"
				expiredCerts += 1
			}

			OvpnClientCertificateExpire.WithLabelValues(line.Identity).Set(float64((parseDateToUnix(indexTxtDateLayout, line.ExpirationDate) - apochNow) / 3600 / 24))

			if (parseDateToUnix(indexTxtDateLayout, line.ExpirationDate) - apochNow) < 0 {
				ovpnClient.AccountStatus = "Expired"
			}
			ovpnClient.Connections = 0

			userConnected, userConnectedTo := isUserConnected(line.Identity, oAdmin.activeClients)
			if userConnected {
				ovpnClient.ConnectionStatus = "Connected"
				for range userConnectedTo {
					ovpnClient.Connections += 1
					totalActiveConnections += 1
				}
				connectedUniqUsers += 1
			}

			if oAdmin.ExtraAuth{
				if oAdmin.isSecondFactorConfigured(ovpnClient.Identity) {
					ovpnClient.SecondFactor = "enabled"
				} else {
					ovpnClient.SecondFactor = "disabled"
				}
			}

			users = append(users, ovpnClient)

		} else {
			OvpnServerCertExpire.Set(float64((parseDateToUnix(indexTxtDateLayout, line.ExpirationDate) - apochNow) / 3600 / 24))
		}
	}

	otherCerts := totalCerts - validCerts - revokedCerts - expiredCerts

	if otherCerts != 0 {
		log.Warnf("there are %d otherCerts", otherCerts)
	}

	OvpnClientsTotal.Set(float64(totalCerts))
	OvpnClientsRevoked.Set(float64(revokedCerts))
	OvpnClientsExpired.Set(float64(expiredCerts))
	OvpnClientsConnected.Set(float64(totalActiveConnections))
	OvpnUniqClientsConnected.Set(float64(connectedUniqUsers))

	return users
}

func (oAdmin *OvpnAdmin) userCreate(username, password string) (string, error) {
	var msg string
	oAdmin.CreateUserMutex.Lock()
	defer oAdmin.CreateUserMutex.Unlock()

	if checkUserExist(username) {
		msg = fmt.Sprintf("User \"%s\" already exists\n", username)
		return msg, userAlreadyExistError
	}

	if err := validateUsername(username); err != nil {
		log.Debugf("userCreate: validateUsername(): %s", err.Error())
		return err.Error(), err
	}

	if oAdmin.ExtraAuth {
		if err := validatePassword(password); err != nil {
			log.Debugf("userCreate: authByPassword(): %s", err.Error())
			return err.Error(), err
		}
	}

	if *StorageBackend == "kubernetes.secrets" {
		err := oAdmin.KubeClient.EasyrsaBuildClient(username)
		if err != nil {
			log.Error(err)
			return err.Error(), err
		}
		if oAdmin.ExtraAuth {
			err = oAdmin.KubeClient.updatePasswordSecret(username, []byte(password))
			if err != nil {
				return err.Error(), err
			}
		}
	} else {
		o := runBash(fmt.Sprintf("cd %s && easyrsa build-client-full %s nopass 1>/dev/null", *EasyrsaDirPath, username))
		log.Debug(o)
		if oAdmin.ExtraAuth {
			_, err := oAdmin.OUser.CreateUser(username, password)
			if err != nil {
				return err.Error(), err
			}
		}
	}

	log.Infof("Certificate for user %s issued", username)

	//oAdmin.clients = oAdmin.usersList()

	return "", nil
}

func (oAdmin *OvpnAdmin) userChangePassword(username, password string) (error, string) {

	if checkUserExist(username) {
		if !oAdmin.OUser.CheckUserExistent(username) {
			_, err := oAdmin.OUser.CreateUser(username, "")
			if err != nil {
				return err, err.Error()
			}
		}

		if err := validatePassword(password); err != nil {
			log.Warningf("userChangePassword: %s", err.Error())
			return err, err.Error()
		}

		if *StorageBackend == "kubernetes.secrets" {
			err := oAdmin.KubeClient.updatePasswordSecret(username, []byte(password))
			if err != nil {
				return err, err.Error()
			}
		} else {
			msg, err := oAdmin.OUser.ChangeUserPassword(username, password)
			if err != nil {
				return err, msg
			}
		}
		log.Infof("Password for user %s was changed", username)

		return nil, "Password changed"
	}

	return errors.New(fmt.Sprintf("User \"%s\" not found}", username)), fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
}

func (oAdmin *OvpnAdmin) isSecondFactorConfigured(username string) bool {

	switch *StorageBackend {
	case "kubernetes.secrets":
		sfe, err := oAdmin.KubeClient.SecondFactorEnabled(username)
		if err != nil {
			return false
		}
		return sfe
	case "filesystem":
		switch *AuthType {
		case "TOTP":
			sfe, err := oAdmin.OUser.IsSecondFactorEnabled(username)
			if err != nil {
				return false
			}
			return sfe
		case "PASSWORD":
			return true
			//TODO: check if password is exist in db
		}
	default:
		return false
	}
	return false
}

func (oAdmin *OvpnAdmin) getUserSecret(username string) (string, error) {
	if checkUserExist(username) {

		var userSecret string
		var err error

		if *StorageBackend == "kubernetes.secrets" {
			userSecret, err = oAdmin.KubeClient.secondFactorSecret(username)
			if err != nil {
				return err.Error(), err
			}
		} else {
			if !oAdmin.OUser.CheckUserExistent(username) {
				_, err = oAdmin.OUser.CreateUser(username, "")
				if err != nil {
					return "", err
				}
			}
			userSecret, err = oAdmin.OUser.GetUserOtpSecret(username)
			if err != nil {
				return "", err
			}
		}

		val, valErr := base32.StdEncoding.DecodeString(userSecret)
		if valErr != nil {
			return "", fmt.Errorf("can`t get user secret")
		}

		if string(val) == "" {

			if *StorageBackend == "kubernetes.secrets" {
				rndStr := ou.RandStr(20, "number")
				newSecret := make([]byte, base32.StdEncoding.EncodedLen(len(rndStr)))

				base32.StdEncoding.Encode(newSecret, []byte(rndStr))
				updUserSecretErr := oAdmin.KubeClient.updateSecondFactorSecret(username, newSecret)
				if updUserSecretErr != nil {
					return "", updUserSecretErr
				}
				userSecret = string(newSecret)
			} else {
				_, updUserSecretErr := oAdmin.OUser.RegisterOtpSecret(username, "generate")
				if updUserSecretErr != nil {
					return "", updUserSecretErr
				}
				userSecret, err = oAdmin.OUser.GetUserOtpSecret(username)
				if err != nil {
					return "", err
				}
			}
			_, err = base32.StdEncoding.DecodeString(userSecret)
			if err != nil {
				return "", fmt.Errorf("can`t get user secret")
			}
			return userSecret, nil
		}
		return userSecret, nil
	}

	return fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username), fmt.Errorf("user \"%s\" not found", username)
}

func (oAdmin *OvpnAdmin) registerUserAuthApp(username, totp string) error {
	if checkUserExist(username) {
		if *StorageBackend == "kubernetes.secrets" {
			authOK, authErr := oAdmin.KubeClient.authByTOTP(username, totp)
			if authErr != nil {
				return authErr
			}

			if authOK {
				err := oAdmin.KubeClient.addSecondFactorEnabledLabel(username)
				if err != nil {
					return err
				}
			}
		} else {
			if !oAdmin.OUser.CheckUserExistent(username) {
				_, createErr := oAdmin.OUser.CreateUser(username, "")
				if createErr != nil {
					return createErr
				}
			}

			_, registerErr := oAdmin.OUser.RegisterOtpApplication(username, totp)
			if registerErr != nil {
				return registerErr
			}
		}

		for i, u := range oAdmin.clients {
			if u.Identity == username {
				oAdmin.clients[i].SecondFactor = "enabled"
			}
		}

		log.Infof("TOTP configured for user %s", username)
		return nil
	}
	return fmt.Errorf("user \"%s\" not found", username)
}

func (oAdmin *OvpnAdmin) resetUserAuthApp(username string) error {

	if checkUserExist(username) {
		if *StorageBackend == "kubernetes.secrets" {

			err := oAdmin.KubeClient.deleteSecondFactorEnabledLabel(username)
			if err != nil {
				return err
			}

		} else {
			_, resetErr := oAdmin.OUser.ResetOtpApplication(username)
			if resetErr != nil {
				return resetErr
			}
		}

		for i, u := range oAdmin.clients {
			if u.Identity == username {
				oAdmin.clients[i].SecondFactor = "disabled"
			}
		}
		return nil
	}

	return fmt.Errorf("user \"%s\" not found", username)
}

func (oAdmin *OvpnAdmin) checkAuth(username, token string) error {

	if checkUserExist(username) {
		var auth bool
		var authErr error
		if *StorageBackend == "kubernetes.secrets" {
			auth, authErr = oAdmin.KubeClient.authByTOTP(username, token)
			if authErr != nil {
				return authErr
			}
		} else {
			switch *AuthType {
			case "TOTP":
				auth, authErr = oAdmin.OUser.AuthUser(username, "", token)
			case "PASSWORD":
				auth, authErr = oAdmin.OUser.AuthUser(username, token, "")
			}
			if authErr != nil {
				return authErr
			}
		}
		if auth {
			return nil
		}
		return fmt.Errorf("authorization failed")
	}

	return fmt.Errorf("user \"%s\" not found", username)
}

func (oAdmin *OvpnAdmin) getUserStatistic(username string) []ClientStatus {
	var userStatistic []ClientStatus
	for _, u := range oAdmin.activeClients {
		if u.CommonName == username {
			userStatistic = append(userStatistic, u)
		}
	}
	return userStatistic
}

func (oAdmin *OvpnAdmin) userRevoke(username string) (error, string) {
	log.Infof("Revoke certificate for user %s", username)
	if checkUserExist(username) {
		// check certificate valid flag 'V'
		if *StorageBackend == "kubernetes.secrets" {
			err := oAdmin.KubeClient.EasyrsaRevoke(username)
			if err != nil {
				log.Error(err)
			}
		} else {
			o := runBash(fmt.Sprintf("cd %s && echo yes | easyrsa revoke %s 1>/dev/null && easyrsa gen-crl 1>/dev/null", *EasyrsaDirPath, username))
			log.Debugln(o)
		}

		if oAdmin.ExtraAuth {
			if oAdmin.OUser.CheckUserExistent(username) {
				revokeMsg, revokeErr := oAdmin.OUser.RevokedUser(username)
				log.Debug(revokeMsg)
				log.Debug(revokeErr)
				if revokeErr != nil {
					return revokeErr, ""
				}
			}
		}

		crlFix()
		userConnected, userConnectedTo := isUserConnected(username, oAdmin.activeClients)
		log.Tracef("User %s connected: %t", username, userConnected)
		if userConnected {
			for _, connection := range userConnectedTo {
				oAdmin.mgmtKillUserConnection(username, connection)
				log.Infof("Session for user \"%s\" killed", username)
			}
		}

		oAdmin.SetState()
		return nil, fmt.Sprintf("user \"%s\" revoked", username)
	}
	log.Infof("user \"%s\" not found", username)
	return fmt.Errorf("user \"%s\" not found", username), fmt.Sprintf("User \"%s\" not found", username)
}

func (oAdmin *OvpnAdmin) userUnrevoke(username string) (error, string) {
	if checkUserExist(username) {
		if *StorageBackend == "kubernetes.secrets" {
			err := oAdmin.KubeClient.EasyrsaUnrevoke(username)
			if err != nil {
				log.Error(err)
			}
		} else {
			// check certificate revoked flag 'R'
			usersFromIndexTxt := IndexTxtParser(fRead(*IndexTxtPath))
			for i := range usersFromIndexTxt {
				if usersFromIndexTxt[i].DistinguishedName == "/CN="+username {
					if usersFromIndexTxt[i].Flag == "R" {

						usersFromIndexTxt[i].Flag = "V"
						usersFromIndexTxt[i].RevocationDate = ""

						err := fMove(fmt.Sprintf("%s/pki/revoked/certs_by_serial/%s.crt", *EasyrsaDirPath, usersFromIndexTxt[i].SerialNumber), fmt.Sprintf("%s/pki/issued/%s.crt", *EasyrsaDirPath, username))
						if err != nil {
							log.Error(err)
						}
						err = fMove(fmt.Sprintf("%s/pki/revoked/certs_by_serial/%s.crt", *EasyrsaDirPath, usersFromIndexTxt[i].SerialNumber), fmt.Sprintf("%s/pki/certs_by_serial/%s.pem", *EasyrsaDirPath, usersFromIndexTxt[i].SerialNumber))
						if err != nil {
							log.Error(err)
						}
						err = fMove(fmt.Sprintf("%s/pki/revoked/private_by_serial/%s.key", *EasyrsaDirPath, usersFromIndexTxt[i].SerialNumber), fmt.Sprintf("%s/pki/private/%s.key", *EasyrsaDirPath, username))
						if err != nil {
							log.Error(err)
						}
						err = fMove(fmt.Sprintf("%s/pki/revoked/reqs_by_serial/%s.req", *EasyrsaDirPath, usersFromIndexTxt[i].SerialNumber), fmt.Sprintf("%s/pki/reqs/%s.req", *EasyrsaDirPath, username))
						if err != nil {
							log.Error(err)
						}
						err = fWrite(*IndexTxtPath, renderIndexTxt(usersFromIndexTxt))
						if err != nil {
							log.Error(err)
						}

						_ = runBash(fmt.Sprintf("cd %s && easyrsa gen-crl 1>/dev/null", *EasyrsaDirPath))

						if oAdmin.ExtraAuth {
							if oAdmin.OUser.CheckUserExistent(username) {
								restoreMsg, restoreErr := oAdmin.OUser.RestoreUser(username)
								log.Debug(restoreMsg)
								log.Debug(restoreErr)
								if restoreErr != nil {
									return restoreErr, ""
								}
							}
						}

						crlFix()

						break
					}
				}
			}
			err := fWrite(*IndexTxtPath, renderIndexTxt(usersFromIndexTxt))
			if err != nil {
				log.Error(err)
			}
		}
		crlFix()
		oAdmin.clients = oAdmin.usersList()
		return nil, fmt.Sprintf("{\"msg\":\"User %s successfully unrevoked\"}", username)
	}
	return fmt.Errorf("user \"%s\" not found", username), fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
}

func (oAdmin *OvpnAdmin) userRotate(username, newPassword string) (error, string) {
	if checkUserExist(username) {
		if *StorageBackend == "kubernetes.secrets" {
			err := oAdmin.KubeClient.EasyrsaRotate(username)
			if err != nil {
				log.Error(err)
			}
		} else {

			var oldUserIndex, newUserIndex int
			var oldUserSerial string

			uniqHash := strings.Replace(uuid.New().String(), "-", "", -1)

			usersFromIndexTxt := IndexTxtParser(fRead(*IndexTxtPath))
			for i := range usersFromIndexTxt {
				if usersFromIndexTxt[i].DistinguishedName == "/CN="+username {
					oldUserSerial = usersFromIndexTxt[i].SerialNumber
					usersFromIndexTxt[i].DistinguishedName = "/CN=REVOKED-" + username + "-" + uniqHash
					oldUserIndex = i
					break
				}
			}
			err := fWrite(*IndexTxtPath, renderIndexTxt(usersFromIndexTxt))
			if err != nil {
				log.Error(err)
			}

			if oAdmin.ExtraAuth {
				if oAdmin.OUser.CheckUserExistent(username) {
					deleteMsg, deleteErr := oAdmin.OUser.DeleteUser(username, true)
					log.Debug(deleteMsg)
					log.Debug(deleteErr)
					if deleteErr != nil {
						return deleteErr, ""
					}
					log.Debug(deleteMsg)
				}
			}

			userCreateMessage, userCreateError := oAdmin.userCreate(username, newPassword)
			if userCreateError != nil {
				usersFromIndexTxt = IndexTxtParser(fRead(*IndexTxtPath))
				for i := range usersFromIndexTxt {
					if usersFromIndexTxt[i].SerialNumber == oldUserSerial {
						usersFromIndexTxt[i].DistinguishedName = "/CN=" + username
						break
					}
				}
				err = fWrite(*IndexTxtPath, renderIndexTxt(usersFromIndexTxt))
				if err != nil {
					log.Error(err)
				}
				return fmt.Errorf("error rotaing user due:  %s", userCreateMessage), userCreateMessage
			}

			usersFromIndexTxt = IndexTxtParser(fRead(*IndexTxtPath))
			for i := range usersFromIndexTxt {
				if usersFromIndexTxt[i].DistinguishedName == "/CN="+username {
					newUserIndex = i
				}
				if usersFromIndexTxt[i].SerialNumber == oldUserSerial {
					oldUserIndex = i
				}
			}
			usersFromIndexTxt[oldUserIndex], usersFromIndexTxt[newUserIndex] = usersFromIndexTxt[newUserIndex], usersFromIndexTxt[oldUserIndex]

			err = fWrite(*IndexTxtPath, renderIndexTxt(usersFromIndexTxt))
			if err != nil {
				log.Error(err)
			}

			_ = runBash(fmt.Sprintf("cd %s && easyrsa gen-crl 1>/dev/null", *EasyrsaDirPath))
		}
		crlFix()
		oAdmin.clients = oAdmin.usersList()
		return nil, fmt.Sprintf("{\"msg\":\"User %s successfully rotated\"}", username)
	}
	return fmt.Errorf("user \"%s\" not found", username), fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
}

func (oAdmin *OvpnAdmin) userDelete(username string) (error, string) {
	if checkUserExist(username) {
		if *StorageBackend == "kubernetes.secrets" {
			err := oAdmin.KubeClient.EasyrsaDelete(username)
			if err != nil {
				log.Error(err)
			}
		} else {
			uniqHash := strings.Replace(uuid.New().String(), "-", "", -1)
			usersFromIndexTxt := IndexTxtParser(fRead(*IndexTxtPath))
			for i := range usersFromIndexTxt {
				if usersFromIndexTxt[i].DistinguishedName == "/CN="+username {
					usersFromIndexTxt[i].DistinguishedName = "/CN=REVOKED-" + username + "-" + uniqHash
					break
				}
			}
			if oAdmin.ExtraAuth {
				if oAdmin.OUser.CheckUserExistent(username) {
					deleteMsg, deleteErr := oAdmin.OUser.DeleteUser(username, true)
					log.Debug(deleteMsg)
					log.Debug(deleteErr)
					if deleteErr != nil {
						log.Debug(deleteErr)
						return deleteErr, ""
					}
				}
			}
			err := fWrite(*IndexTxtPath, renderIndexTxt(usersFromIndexTxt))
			if err != nil {
				log.Error(err)
			}
			_ = runBash(fmt.Sprintf("cd %s && easyrsa gen-crl 1>/dev/null ", *EasyrsaDirPath))
		}
		crlFix()
		oAdmin.clients = oAdmin.usersList()
		return nil, fmt.Sprintf("{\"msg\":\"User %s successfully deleted\"}", username)
	}
	return fmt.Errorf("user \"%s\" not found", username), fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
}

func (oAdmin *OvpnAdmin) mgmtRead(conn net.Conn) string {
	recvData := make([]byte, 32768)
	var out string
	var n int
	var err error
	for {
		n, err = conn.Read(recvData)
		if n <= 0 || err != nil {
			break
		} else {
			out += string(recvData[:n])
			if strings.Contains(out, "type 'help' for more info") || strings.Contains(out, "END") || strings.Contains(out, "SUCCESS:") || strings.Contains(out, "ERROR:") {
				break
			}
		}
	}
	return out
}

func (oAdmin *OvpnAdmin) mgmtConnectedUsersParser(text, serverName string) []ClientStatus {
	var u []ClientStatus
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

			userStatus := ClientStatus{CommonName: userName, RealAddress: userAddress, BytesReceived: userBytesReceived, BytesSent: userBytesSent, ConnectedSince: userConnectedSince, ConnectedTo: serverName}
			u = append(u, userStatus)
			bytesSent, _ := strconv.Atoi(userBytesSent)
			bytesReceive, _ := strconv.Atoi(userBytesReceived)
			OvpnClientConnectionFrom.WithLabelValues(userName, userAddress).Set(float64(parseDateToUnix(oAdmin.mgmtStatusTimeFormat, userConnectedSince)))
			OvpnClientBytesSent.WithLabelValues(userName).Set(float64(bytesSent))
			OvpnClientBytesReceived.WithLabelValues(userName).Set(float64(bytesReceive))
		}
		if isRouteTable {
			user := strings.Split(txt, ",")
			for i := range u {
				if u[i].CommonName == user[1] {
					u[i].VirtualAddress = user[0]
					u[i].RealAddress = user[2]
					u[i].LastRef = user[3]
					OvpnClientConnectionInfo.WithLabelValues(user[1], user[0], user[2]).Set(float64(parseDateToUnix(oAdmin.mgmtStatusTimeFormat, user[3])))
					break
				}
			}
		}
	}
	return u
}

func (oAdmin *OvpnAdmin) mgmtKillUserConnection(username, serverName string) {
	conn, err := net.Dial("tcp", oAdmin.MgmtInterfaces[serverName])
	if err != nil {
		log.Errorf("openvpn mgmt interface for %s is not reachable by addr %s", serverName, oAdmin.MgmtInterfaces[serverName])
		return
	}
	oAdmin.mgmtRead(conn) // read welcome message
	conn.Write([]byte(fmt.Sprintf("kill %s\n", username)))
	fmt.Printf("%v", oAdmin.mgmtRead(conn))
	conn.Close()
}

func (oAdmin *OvpnAdmin) mgmtGetActiveClients() []ClientStatus {
	var activeClients []ClientStatus

	for srv, addr := range oAdmin.MgmtInterfaces {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			log.Warnf("openvpn mgmt interface for %s is not reachable by addr %s", srv, addr)
			break
		}
		oAdmin.mgmtRead(conn) // read welcome message
		conn.Write([]byte("status 1\n"))
		activeClients = append(activeClients, oAdmin.mgmtConnectedUsersParser(oAdmin.mgmtRead(conn), srv)...)
		conn.Close()
	}
	return activeClients
}

func (oAdmin *OvpnAdmin) MgmtSetTimeFormat() {
	// time format for version 2.5 and may be newer
	oAdmin.mgmtStatusTimeFormat = "2006-01-02 15:04:05"
	log.Debugf("mgmtStatusTimeFormat: %s", oAdmin.mgmtStatusTimeFormat)

	type serverVersion struct {
		name    string
		version string
	}

	var serverVersions []serverVersion

	for srv, addr := range oAdmin.MgmtInterfaces {

		var conn net.Conn
		var err error
		for connAttempt := 0; connAttempt < 10; connAttempt++ {
			conn, err = net.Dial("tcp", addr)
			if err == nil {
				log.Debugf("mgmtSetTimeFormat: successful connection to %s/%s", srv, addr)
				break
			}
			log.Warnf("mgmtSetTimeFormat: openvpn mgmt interface for %s is not reachable by addr %s", srv, addr)
			time.Sleep(time.Duration(2) * time.Second)
		}
		if err != nil {
			break
		}

		oAdmin.mgmtRead(conn) // read welcome message
		conn.Write([]byte("version\n"))
		out := oAdmin.mgmtRead(conn)
		conn.Close()

		log.Trace(out)

		for _, s := range strings.Split(out, "\n") {
			if strings.Contains(s, "OpenVPN Version:") {
				serverVersions = append(serverVersions, serverVersion{srv, strings.Split(s, " ")[3]})
				break
			}
		}
	}

	if len(serverVersions) == 0 {
		return
	}

	firstVersion := serverVersions[0].version

	if strings.HasPrefix(firstVersion, "2.4") {
		oAdmin.mgmtStatusTimeFormat = time.ANSIC
		log.Debugf("mgmtStatusTimeFormat changed: %s", oAdmin.mgmtStatusTimeFormat)
	}

	warn := ""
	for _, v := range serverVersions {
		if firstVersion != v.version {
			warn = "mgmtSetTimeFormat: servers have different versions of openvpn, user connection status may not work"
			log.Warn(warn)
			break
		}
	}

	if warn != "" {
		for _, v := range serverVersions {
			log.Infof("server name: %s, version: %s", v.name, v.version)
		}
	}
}

func (oAdmin *OvpnAdmin) downloadCerts() bool {
	if fExist(certsArchivePath) {
		err := fDelete(certsArchivePath)
		if err != nil {
			log.Error(err)
		}
	}

	err := fDownload(certsArchivePath, *masterHost+DownloadCertsApiUrl+"?token="+oAdmin.MasterSyncToken, oAdmin.MasterHostBasicAuth)
	if err != nil {
		log.Error(err)
		return false
	}

	return true
}

func (oAdmin *OvpnAdmin) downloadCcd() bool {
	if fExist(ccdArchivePath) {
		err := fDelete(ccdArchivePath)
		if err != nil {
			log.Error(err)
		}
	}

	err := fDownload(ccdArchivePath, *masterHost+DownloadCcdApiUrl+"?token="+oAdmin.MasterSyncToken, oAdmin.MasterHostBasicAuth)
	if err != nil {
		log.Error(err)
		return false
	}

	return true
}

func (oAdmin *OvpnAdmin) SyncDataFromMaster() {
	retryCountMax := 3
	certsDownloadFailed := true
	ccdDownloadFailed := true

	for certsDownloadRetries := 0; certsDownloadRetries < retryCountMax; certsDownloadRetries++ {
		log.Infof("Downloading archive with certificates from master. Attempt %d", certsDownloadRetries)
		if oAdmin.downloadCerts() {
			certsDownloadFailed = false
			log.Info("Decompressing archive with certificates from master")
			unArchiveCerts()
			log.Info("Decompression archive with certificates from master completed")
			break
		} else {
			log.Warnf("Something goes wrong during downloading archive with certificates from master. Attempt %d", certsDownloadRetries)
		}
	}

	for ccdDownloadRetries := 0; ccdDownloadRetries < retryCountMax; ccdDownloadRetries++ {
		log.Infof("Downloading archive with ccd from master. Attempt %d", ccdDownloadRetries)
		if oAdmin.downloadCcd() {
			ccdDownloadFailed = false
			log.Info("Decompressing archive with ccd from master")
			unArchiveCcd()
			log.Info("Decompression archive with ccd from master completed")
			break
		} else {
			log.Warnf("Something goes wrong during downloading archive with ccd from master. Attempt %d", ccdDownloadRetries)
		}
	}

	oAdmin.LastSyncTime = time.Now().Format(stringDateFormat)
	if !ccdDownloadFailed && !certsDownloadFailed {
		oAdmin.LastSuccessfulSyncTime = time.Now().Format(stringDateFormat)
	}
}

func (oAdmin *OvpnAdmin) SyncWithMaster() {
	for {
		time.Sleep(time.Duration(*masterSyncFrequency) * time.Second)
		oAdmin.SyncDataFromMaster()
	}
}

func (oAdmin *OvpnAdmin) IsTotpAuth() bool {
	if IsModuleEnabled("totpAuth", oAdmin.Modules) {
		return true
	} 
	return false
}

func (oAdmin *OvpnAdmin) IsPasswdAuth() bool {
	if IsModuleEnabled("passwdAuth", oAdmin.Modules) {
		return true
	} 
	return false
}
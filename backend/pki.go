package backend

import (
    "bytes"
    "strings"
    "context"
    "errors"
    "fmt"
    "os"
    "os/exec"
    "sort"
    "time"

    "github.com/google/uuid"
    log "github.com/sirupsen/logrus"
    v1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (openVPNPKI *OpenVPNPKI) InitPKI() (err error) {
    err = openVPNPKI.initCA()
    if err != nil {
        return err
    }

    err = openVPNPKI.initSecretServer()
    if err != nil {
        return err
    }

    err = openVPNPKI.initIndexTxt()
    if err != nil {
        log.Error(err)
    }

    err = openVPNPKI.GenPemCRL()
    if err != nil {
        log.Error(err)
    }

    err = openVPNPKI.initTaKeyAndDHParam()
    if err != nil {
        log.Error(err)
    }

    err = openVPNPKI.updateFiles()
    if err != nil {
        log.Error(err)
    }


    return
}

func (openVPNPKI *OpenVPNPKI) initCA() (err error) {
    if openVPNPKI.checkExistData(secretCA) {
        cert, err := openVPNPKI.getExistCert(secretCA)
        if err != nil {
            return err
        }
        openVPNPKI.CAPrivKeyPEM = cert.PrivKeyPEM
        openVPNPKI.CAPrivKeyRSA = cert.PrivKeyRSA
        openVPNPKI.CACertPEM = cert.CertPEM
        openVPNPKI.CACert = cert.Cert
    } else {
        cert := openVPNPKI.generateKeyPair()
        openVPNPKI.CAPrivKeyPEM = cert.PrivKeyPEM
        openVPNPKI.CAPrivKeyRSA = cert.PrivKeyRSA
        openVPNPKI.CACertPEM = cert.CertPEM
        openVPNPKI.CACert = cert.Cert
    }
    return
}

func (openVPNPKI *OpenVPNPKI) generateKeyPair() (cert ClientCert) {
    var err error
    cert.PrivKeyPEM, err = GenPrivKey()
    if err != nil {
        return
    }
    cert.PrivKeyRSA, err = DecodePrivKey(cert.PrivKeyPEM.Bytes())
    if err != nil {
        return
    }
    cert.CertPEM, err = GenCA(cert.PrivKeyRSA)
    if err != nil {
        return
    }
    cert.Cert, err = DecodeCert(cert.CertPEM.Bytes())
    if err != nil {
        return
    }
    return cert
}

func (openVPNPKI *OpenVPNPKI) initSecretServer() (err error) {

    if openVPNPKI.checkExistData(secretServer) {
        cert, err := openVPNPKI.getExistCert(secretServer)
        if err != nil {
            return err
        }
        openVPNPKI.ServerPrivKeyPEM = cert.PrivKeyPEM
        openVPNPKI.ServerPrivKeyRSA = cert.PrivKeyRSA
        openVPNPKI.ServerCertPEM = cert.CertPEM
        openVPNPKI.ServerCert = cert.Cert
    } else {
        cert := openVPNPKI.generateKeyPair()
        openVPNPKI.ServerPrivKeyPEM = cert.PrivKeyPEM
        openVPNPKI.ServerPrivKeyRSA = cert.PrivKeyRSA
        openVPNPKI.ServerCertPEM = cert.CertPEM
        openVPNPKI.ServerCert = cert.Cert

        if err != nil {
            return err
        }
    }

    return
}

func (openVPNPKI *OpenVPNPKI) checkExistData(dataName string) (res bool) {
    switch *StorageBackend {
    case "kubernetes.secrets":
        res, _ = openVPNPKI.secretCheckExists(dataName)
    case "filesystem":
        if dataName == secretCA {
            res = fExist(fmt.Sprintf("%s/pki/ca.crt", *EasyrsaDirPath))
        } else if dataName == secretServer{
            res = fExist(fmt.Sprintf("%s/pki/issued/server.crt", *EasyrsaDirPath))
        }
    }
    return res
}

func (openVPNPKI *OpenVPNPKI) getExistCert(name string) (data ClientCert, err error) {
    switch *StorageBackend {

    case "kubernetes.secrets":
        data, err = openVPNPKI.secretGetClientCert(name)

    case "filesystem":
        var crtPath,keyPath string

        if name == secretCA {
            crtPath = fmt.Sprintf("%s/pki/ca.crt", *EasyrsaDirPath)
            keyPath = fmt.Sprintf("%s/pki/private/ca.key", *EasyrsaDirPath)
        } else if name == secretServer {
            crtPath = fmt.Sprintf("%s/pki/issued/server.crt", *EasyrsaDirPath)
            keyPath = fmt.Sprintf("%s/pki/private/server.key", *EasyrsaDirPath)
        } else {
            // TODO: check how used this
            crtPath = fmt.Sprintf("%s/pki/issued/%s.crt", *EasyrsaDirPath, name)
        }

        certData := fReadRaw(crtPath)
        data.CertPEM = bytes.NewBuffer(certData)
        data.Cert, err = DecodeCert(data.CertPEM.Bytes())
        if err != nil {
            return
        }

        if len(keyPath) > 0 {
            privKeyData := fReadRaw(keyPath)
            data.PrivKeyPEM = bytes.NewBuffer(privKeyData)
            data.PrivKeyRSA, err = DecodePrivKey(data.PrivKeyPEM.Bytes())
            if err != nil {
                return
            }
        }

    }
    return data, err
}

func (openVPNPKI *OpenVPNPKI) BuildKeyPairClient(commonName string) (err error) {

    switch *StorageBackend {
    case "kubernetes.secrets":
        // check certificate exists
        _, err = openVPNPKI.secretGetByLabels("name=" + commonName)
        if err == nil {
            return fmt.Errorf("certificate for user (%s) already exists", commonName)
        }


        clientPrivKeyPEM, _ := GenPrivKey()
        clientPrivKeyRSA, _ := DecodePrivKey(clientPrivKeyPEM.Bytes())
        clientCertPEM, _ := GenClientCert(clientPrivKeyRSA, openVPNPKI.CAPrivKeyRSA, openVPNPKI.CACert, commonName)
        clientCert, _ := DecodeCert(clientCertPEM.Bytes())

        secretMetaData := metav1.ObjectMeta{
            Name: fmt.Sprintf(secretClientTmpl, clientCert.SerialNumber),
            Labels: map[string]string{
                "index.txt":                    "",
                "type":                         "clientAuth",
                "name":                         commonName,
                "app.kubernetes.io/managed-by": "ovpn-admin",
            },
            Annotations: map[string]string{
                "commonName":   commonName,
                "notBefore":    clientCert.NotBefore.Format(indexTxtDateFormat),
                "notAfter":     clientCert.NotAfter.Format(indexTxtDateFormat),
                "revokedAt":    "",
                "serialNumber": fmt.Sprintf("%d", clientCert.SerialNumber),
            },
        }
    
        secretData := map[string][]byte{
            certFileName:    clientCertPEM.Bytes(),
            privKeyFileName: clientPrivKeyPEM.Bytes(),
        }
    
        err = openVPNPKI.secretCreate(secretMetaData, secretData, v1.SecretTypeTLS)
        if err != nil {
            return
        }
    case "filesystem":
        
        if checkUserExist(commonName) {
            return errors.New(fmt.Sprintf("certificate for user (%s) already exists", commonName))
        }

        clientPrivKeyPEM, _ := GenPrivKey()
        clientPrivKeyRSA, _ := DecodePrivKey(clientPrivKeyPEM.Bytes())
        clientCertPEM, _ := GenClientCert(clientPrivKeyRSA, openVPNPKI.CAPrivKeyRSA, openVPNPKI.CACert, commonName)
        clientCert, _ := DecodeCert(clientCertPEM.Bytes())

        err = fWriteRaw(fmt.Sprintf("%s/pki/issued/%s.crt", *EasyrsaDirPath, commonName), clientCertPEM.Bytes(), 0644)
        if err != nil {
            return err
        }
        err = fWriteRaw(fmt.Sprintf("%s/pki/private/%s.key", *EasyrsaDirPath, commonName), clientPrivKeyPEM.Bytes(), 0600)
        if err != nil {
            return err
        }

        err = fWriteRaw(fmt.Sprintf("%s/pki/certs_by_serial/%X.pem", *EasyrsaDirPath, clientCert.SerialNumber), clientCertPEM.Bytes(), 0600)
        if err != nil {
            return err
        }

        }


    err = openVPNPKI.indexTxtUpdate()
    if err != nil {
        return err
    }

    if *StorageBackend == "kubernetes.secret" {
        err = openVPNPKI.updateIndexTxtOnDisk()
        if err != nil {
            return err
        }
    }

    return
}


func (openVPNPKI *OpenVPNPKI) initIndexTxt() (err error) {
    var indexTxt string
    
    switch *StorageBackend {
    case "kubernetes.secrets":
        secrets, err := openVPNPKI.secretsGetByLabels("index.txt=")
        if err != nil {
            return err
        }

        
        for _, secret := range secrets.Items {
            certPEM := bytes.NewBuffer(secret.Data[certFileName])
            log.Trace("indexTxtUpdate:" + secret.Name)
            cert, err := DecodeCert(certPEM.Bytes())
            if err != nil {
                return nil
            }

            log.Trace(cert.Subject.CommonName)

            if secret.Annotations["revokedAt"] == "" {
                indexTxt += fmt.Sprintf("%s\t%s\t\t%s\t%s\t%s\n", "V", cert.NotAfter.Format(indexTxtDateFormat), fmt.Sprintf("%d", cert.SerialNumber), "unknown", "/CN="+secret.Labels["name"])
            } else if cert.NotAfter.Before(time.Now()) {
                indexTxt += fmt.Sprintf("%s\t%s\t\t%s\t%s\t%s\n", "E", cert.NotAfter.Format(indexTxtDateFormat), fmt.Sprintf("%d", cert.SerialNumber), "unknown", "/CN="+secret.Labels["name"])
            } else {
                indexTxt += fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\n", "R", cert.NotAfter.Format(indexTxtDateFormat), secret.Annotations["revokedAt"], fmt.Sprintf("%d", cert.SerialNumber), "unknown", "/CN="+secret.Labels["name"])
            }

        }

        secretMetaData := metav1.ObjectMeta{Name: secretIndexTxt}

        secretData := map[string][]byte{"index.txt": []byte(indexTxt)}

        if res, _ := openVPNPKI.secretCheckExists(secretIndexTxt); !res {
            err = openVPNPKI.secretCreate(secretMetaData, secretData, v1.SecretTypeOpaque)
        } else {
            err = openVPNPKI.secretUpdate(secretMetaData, secretData, v1.SecretTypeOpaque)
        }
    case "filesystem":
        if _, err := os.Stat(fmt.Sprintf("%s/pki/issued", *EasyrsaDirPath)); os.IsNotExist(err) {
            err = os.MkdirAll(fmt.Sprintf("%s/pki/issued", *EasyrsaDirPath), 0755)
            return err
        }
    
        if _, err := os.Stat(fmt.Sprintf("%s/pki/private", *EasyrsaDirPath)); os.IsNotExist(err) {
            err = os.MkdirAll(fmt.Sprintf("%s/pki/private", *EasyrsaDirPath), 0755)
            return err
        }
    
        if !fExist(*EasyrsaDirPath+"/pki/index.txt") {
            path := *EasyrsaDirPath+"/pki/issued/"
            files := fReadDir(path)
            for _, file := range files {
                certData := fReadRaw(path+file.Name())
                certPEM := bytes.NewBuffer(certData)
                log.Trace("indexTxtUpdate:" + file.Name())
                cert, err := DecodeCert(certPEM.Bytes())
                if err != nil {
                    return nil
                }
                log.Trace(cert.Subject.CommonName)
    
                if cert.NotAfter.Before(time.Now()) {
                    indexTxt += fmt.Sprintf("%s\t%s\t\t%s\t%s\t%s\n", "E", cert.NotAfter.Format(indexTxtDateFormat), fmt.Sprintf("%X", cert.SerialNumber), "unknown", "/CN="+cert.Subject.CommonName)
                } else {
                    indexTxt += fmt.Sprintf("%s\t%s\t\t%s\t%s\t%s\n", "V", cert.NotAfter.Format(indexTxtDateFormat), fmt.Sprintf("%X", cert.SerialNumber), "unknown", "/CN="+cert.Subject.CommonName)
                }
            }
            path = *EasyrsaDirPath+"/pki/revoked/certs_by_serial/"
            if fExist(path){
              filesRevoke := fReadDir(path)
              for _, file := range filesRevoke {
                  certData := fReadRaw(path+file.Name())
                  certPEM := bytes.NewBuffer(certData)
                  log.Trace("indexTxtUpdate:" + file.Name())
                  cert, err := DecodeCert(certPEM.Bytes())
                  if err != nil {
                      return nil
                  }
                  log.Trace(cert.Subject.CommonName)
      
                  indexTxt += fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\n", "R", cert.NotAfter.Format(indexTxtDateFormat), time.Now().Format(indexTxtDateFormat), fmt.Sprintf("%X", cert.SerialNumber), "unknown", "/CN=REVOKED-"+cert.Subject.CommonName)
              }
            }
            err = fWrite(*EasyrsaDirPath+"/pki/index.txt", indexTxt)
            if err != nil {
                return err
            }
        }
    }
    return
}


func (openVPNPKI *OpenVPNPKI) indexTxtUpdate() (err error) {
    
    switch *StorageBackend {
    case "kubernetes.secrets":
        var indexTxt string
        secrets, err := openVPNPKI.secretsGetByLabels("index.txt=")
        if err != nil {
            return err
        }

        for _, secret := range secrets.Items {
            certPEM := bytes.NewBuffer(secret.Data[certFileName])
            log.Trace("indexTxtUpdate:" + secret.Name)
            cert, err := DecodeCert(certPEM.Bytes())
            if err != nil {
                return err
            }

            log.Trace(cert.Subject.CommonName)

            if secret.Annotations["revokedAt"] == "" {
                indexTxt += fmt.Sprintf("%s\t%s\t\t%s\t%s\t%s\n", "V", cert.NotAfter.Format(indexTxtDateFormat), fmt.Sprintf("%d", cert.SerialNumber), "unknown", "/CN="+secret.Labels["name"])
            } else if cert.NotAfter.Before(time.Now()) {
                indexTxt += fmt.Sprintf("%s\t%s\t\t%s\t%s\t%s\n", "E", cert.NotAfter.Format(indexTxtDateFormat), fmt.Sprintf("%d", cert.SerialNumber), "unknown", "/CN="+secret.Labels["name"])
            } else {
                indexTxt += fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\n", "R", cert.NotAfter.Format(indexTxtDateFormat), secret.Annotations["revokedAt"], fmt.Sprintf("%d", cert.SerialNumber), "unknown", "/CN="+secret.Labels["name"])
            }
        }

        secretMetaData := metav1.ObjectMeta{Name: secretIndexTxt}
        secretData := map[string][]byte{"index.txt": []byte(indexTxt)}

        if res, _ := openVPNPKI.secretCheckExists(secretIndexTxt); !res {
            err = openVPNPKI.secretCreate(secretMetaData, secretData, v1.SecretTypeOpaque)
        } else {
            err = openVPNPKI.secretUpdate(secretMetaData, secretData, v1.SecretTypeOpaque)
        }
    case "filesystem":
        indexTxtFromFile := GetIndexTxt(fRead(*IndexTxtPath))
        path := *EasyrsaDirPath+"/pki/issued/"
        files := fReadDir(path)
        for _, file := range files {
            certData := fReadRaw(path+file.Name())
            certPEM := bytes.NewBuffer(certData)
            log.Trace("indexTxtUpdate:" + file.Name())
            cert, err := DecodeCert(certPEM.Bytes())
            if err != nil {
                return err
            }
            log.Trace(cert.Subject.CommonName)

            identity := string(cert.Subject.CommonName)
            if cert.NotAfter.Before(time.Now()) {
                if existIndex, ok := indexTxtFromFile[identity]; ok {
                    existIndex.Flag = "E"
                    indexTxtFromFile[identity] = existIndex
                } else {
                    indexTxtFromFile[identity] = indexTxtLine { 
                        Flag: "E",
                        ExpirationDate: cert.NotAfter.Format(indexTxtDateFormat),
                        SerialNumber: fmt.Sprintf("%X", cert.SerialNumber),
                        Filename: "unknown",
                        DistinguishedName: "/CN="+cert.Subject.CommonName,
                        Identity: "cert.Subject.CommonName",
                        }
                }
            } else {
                indexTxtFromFile[identity] = indexTxtLine { 
                    Flag: "V",
                    ExpirationDate: cert.NotAfter.Format(indexTxtDateFormat),
                    SerialNumber: fmt.Sprintf("%X", cert.SerialNumber),
                    Filename: "unknown",
                    DistinguishedName: "/CN="+cert.Subject.CommonName,
                    Identity: "cert.Subject.CommonName",
                    }

            }
        }

        path = *EasyrsaDirPath+"/pki/revoked/certs_by_serial/"
        filesRevoke := fReadDir(path)
        for _, file := range filesRevoke {
          if !strings.Contains(file.Name(), "-del-") { 
            certData := fReadRaw(path+file.Name())
            certPEM := bytes.NewBuffer(certData)
            log.Trace("indexTxtUpdate:" + file.Name())
            cert, err := DecodeCert(certPEM.Bytes())
            if err != nil {
                return err
            }
            log.Trace(cert.Subject.CommonName)

            identity := string(cert.Subject.CommonName)
            if existIndex, ok := indexTxtFromFile[identity]; ok {
                existIndex.Identity = "/CN="+cert.Subject.CommonName
                if len(existIndex.RevocationDate)== 0 {
                    existIndex.RevocationDate = time.Now().Format(indexTxtDateFormat)
                }
                existIndex.Flag = "R"
                indexTxtFromFile[identity] = existIndex
            }
          }
        }

        var body []string
        keys := make([]string, 0)
        for k, _ := range indexTxtFromFile {
            keys = append(keys, k)
        }
        sort.Strings(keys)
        for _, k := range keys {
          body = append(body, fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\n", indexTxtFromFile[k].Flag, indexTxtFromFile[k].ExpirationDate, indexTxtFromFile[k].RevocationDate, indexTxtFromFile[k].SerialNumber, indexTxtFromFile[k].Filename, indexTxtFromFile[k].DistinguishedName))
        }

        err = fWrite(*EasyrsaDirPath+"/pki/index.txt", strings.Join(body, ""))
        if err != nil {
            return err
        }
    }
    return
}


func (openVPNPKI *OpenVPNPKI) GenPemCRL() (err error) {

    var revoked []*RevokedCert

    err = openVPNPKI.indexTxtUpdate()
    if err != nil {
        return
    }

    switch *StorageBackend {
    case "kubernetes.secrets":
        secrets, err := openVPNPKI.secretsGetByLabels("index.txt=,type=clientAuth")
        if err != nil {
            log.Errorf("error geting secret by label:%s", err.Error())
        }

        for _, secret := range secrets.Items {
            if secret.Annotations["revokedAt"] != "" {
                revokedAt, err := time.Parse(indexTxtDateFormat, secret.Annotations["revokedAt"])
                if err != nil {
                    log.Warning(err)
                }
            cert, err := DecodeCert(secret.Data[certFileName])
            revoked = append(revoked, &RevokedCert{RevokedTime: revokedAt, Cert: cert})
            }
        }
        crl, err := GenCRL(revoked, openVPNPKI.CACert, openVPNPKI.CAPrivKeyRSA)
        if err != nil {
            return err
        }
        secretMetaData := metav1.ObjectMeta{Name: secretCRL}
        secretData := map[string][]byte{
            "crl.pem": crl.Bytes(),
        }

        if res, _ := openVPNPKI.secretCheckExists(secretCRL); !res {
            err = openVPNPKI.secretCreate(secretMetaData, secretData, v1.SecretTypeOpaque)
        } else {
            err = openVPNPKI.secretUpdate(secretMetaData, secretData, v1.SecretTypeOpaque)
        }
    case "filesystem":
        path := *EasyrsaDirPath+"/pki/revoked/certs_by_serial/"
        indexTxtFromFile := GetIndexTxt(fRead(*IndexTxtPath))
        filesRevoke := fReadDir(path)
        
        for _, file := range filesRevoke {
            var identity string
            var revokedAt time.Time
            certData := fReadRaw(path+file.Name())
            certPEM := bytes.NewBuffer(certData)
            log.Trace("indexTxtUpdate:" + file.Name())
            cert, err := DecodeCert(certPEM.Bytes())
            if err != nil {
                log.Errorf("error decode revoked cert:%s", err.Error())
            }
            if strings.Contains(file.Name(), "-del-"){
              trimName := strings.TrimSuffix(file.Name(), ".crt")
              serialN := strings.Split(trimName, "-del-")[1]
              identity = fmt.Sprintf("REVOKED-%s-%s",cert.Subject.CommonName, serialN)
            } else {
              identity = string(cert.Subject.CommonName)
            }
            if existIndex, ok := indexTxtFromFile[identity]; ok {

                revokedAt, err = time.Parse(indexTxtDateFormat, existIndex.RevocationDate)

            } else {
              revokedAt = time.Now()
            }
            if err != nil {
                return err
            }
            revoked = append(revoked, &RevokedCert{RevokedTime: revokedAt, Cert: cert})
        }
        crl, _ := GenCRL(revoked, openVPNPKI.CACert, openVPNPKI.CAPrivKeyRSA)

        err = fWriteRaw(fmt.Sprintf("%s/pki/crl.pem", *EasyrsaDirPath), crl.Bytes(), 0600)
        if err != nil {
            log.Errorf("error write crl.pem:%s", err.Error())
            return err
        }
    }
    return
}


func (openVPNPKI *OpenVPNPKI) initTaKeyAndDHParam() (err error) {
    taKeyPath := fmt.Sprintf("%s/pki/ta.key", *EasyrsaDirPath)
    dhparamPath := fmt.Sprintf("%s/pki/dh.pem", *EasyrsaDirPath)
    switch *StorageBackend {

        case "kubernetes.secrets":
            if res, _ := openVPNPKI.secretCheckExists(secretDHandTA); !res {
                taKey, dhparam := openVPNPKI.generateTaKeyAndDHParam()
                secretMetaData := metav1.ObjectMeta{Name: secretDHandTA}
            
                secretData := map[string][]byte{
                    "ta.key": taKey,
                    "dh.pem": dhparam,
                }
                
                err = openVPNPKI.secretCreate(secretMetaData, secretData, v1.SecretTypeOpaque)
                if err != nil {
                    return err
                }
                openVPNPKI.TaKey = bytes.NewBuffer(taKey)
                openVPNPKI.DhParam = bytes.NewBuffer(dhparam)
            } else {
                taKey := fReadRaw(taKeyPath)
                dhparam := fReadRaw(dhparamPath)
                openVPNPKI.TaKey = bytes.NewBuffer(taKey)
                openVPNPKI.DhParam = bytes.NewBuffer(dhparam)

            }
            
        case "filesystem":
            if res := fExist(taKeyPath); !res {
                taKey, dhparam := openVPNPKI.generateTaKeyAndDHParam()
                openVPNPKI.TaKey = bytes.NewBuffer(taKey)
                openVPNPKI.DhParam = bytes.NewBuffer(dhparam)
            } else{
                taKey := fReadRaw(taKeyPath)
                dhparam := fReadRaw(dhparamPath)
                openVPNPKI.TaKey = bytes.NewBuffer(taKey)
                openVPNPKI.DhParam = bytes.NewBuffer(dhparam)
            }
    }
    return
}

func (openVPNPKI *OpenVPNPKI) generateTaKeyAndDHParam() (taKey []byte, dhparam []byte) { 
    taKeyPath := fmt.Sprintf("%s/pki/ta.key", *EasyrsaDirPath)
    cmd := exec.Command("bash", "-c", fmt.Sprintf("/usr/sbin/openvpn --genkey secret %s", taKeyPath))
    stdout, err := cmd.CombinedOutput()
    log.Info(fmt.Sprintf("/usr/sbin/openvpn --genkey secret %s: %s", taKeyPath, string(stdout)))
    if err != nil {
        return
    }
    taKey = fReadRaw(taKeyPath)

    dhparamPath := fmt.Sprintf("%s/pki//dh.pem", *EasyrsaDirPath)
    cmd = exec.Command("bash", "-c", fmt.Sprintf("openssl dhparam -out %s 2048", dhparamPath))
    _, err = cmd.CombinedOutput()
    if err != nil {
        return
    }
    dhparam = fReadRaw(dhparamPath)

    return taKey, dhparam
}



func (openVPNPKI *OpenVPNPKI) updateFiles() (err error) {

    caPath := fmt.Sprintf("%s/pki/ca.crt", *EasyrsaDirPath)
    caKeyPath := fmt.Sprintf("%s/pki/private/ca.key", *EasyrsaDirPath)

    serverCAPath := fmt.Sprintf("%s/pki/issued/server.crt", *EasyrsaDirPath)
    serverKeyPath := fmt.Sprintf("%s/pki/private/server.key", *EasyrsaDirPath)

    taKeyPath := fmt.Sprintf("%s/pki/ta.key", *EasyrsaDirPath)
    dhparamPath := fmt.Sprintf("%s/pki/dh.pem", *EasyrsaDirPath)


    if *StorageBackend == "kubernetes.secrets"{
        err = openVPNPKI.updateCRLOnDisk()
        if err != nil {
            return err
        }
    }



    if _, err := os.Stat(fmt.Sprintf("%s/pki/issued", *EasyrsaDirPath)); os.IsNotExist(err) {
        err = os.MkdirAll(fmt.Sprintf("%s/pki/issued", *EasyrsaDirPath), 0755)
    }

    if _, err := os.Stat(fmt.Sprintf("%s/pki/private", *EasyrsaDirPath)); os.IsNotExist(err) {
        err = os.MkdirAll(fmt.Sprintf("%s/pki/private", *EasyrsaDirPath), 0755)
    }

    if _, err := os.Stat(fmt.Sprintf("%s/pki/certs_by_serial", *EasyrsaDirPath)); os.IsNotExist(err) {
        err = os.MkdirAll(fmt.Sprintf("%s/pki/certs_by_serial", *EasyrsaDirPath), 0755)
    }

    if _, err := os.Stat(fmt.Sprintf("%s/pki/revoked/private_by_serial", *EasyrsaDirPath)); os.IsNotExist(err) {
        err = os.MkdirAll(fmt.Sprintf("%s/pki/revoked/private_by_serial", *EasyrsaDirPath), 0755)
    }

    if _, err := os.Stat(fmt.Sprintf("%s/pki/revoked/certs_by_serial", *EasyrsaDirPath)); os.IsNotExist(err) {
        err = os.MkdirAll(fmt.Sprintf("%s/pki/revoked/certs_by_serial", *EasyrsaDirPath), 0755)
    }


    if !fExist(caPath){
        err = os.WriteFile(caPath, openVPNPKI.CACertPEM.Bytes(), 0600)
        if err != nil {
            log.Error(err)
        }
        err = os.WriteFile(caKeyPath, openVPNPKI.CAPrivKeyPEM.Bytes(), 0600)
        if err != nil {
            log.Error(err)
        }
    }

    if !fExist(serverCAPath){
        err = os.WriteFile(serverCAPath, openVPNPKI.ServerCertPEM.Bytes(), 0600)
        if err != nil {
            log.Error(err)
        }
    
        err = os.WriteFile(serverKeyPath, openVPNPKI.ServerPrivKeyPEM.Bytes(), 0600)
        if err != nil {
            log.Error(err)
        }
    }
    
    if !fExist(taKeyPath) {
        err = os.WriteFile(taKeyPath, openVPNPKI.TaKey.Bytes(), 0600)
        if err != nil {
            log.Error(err)
        }
    }

    if !fExist(dhparamPath) {
        err = os.WriteFile(dhparamPath, openVPNPKI.DhParam.Bytes(), 0600)
        if err != nil {
            log.Error(err)
        }
    }
    return
}



func (openVPNPKI *OpenVPNPKI) CertificateRevoke(commonName string) (err error) {

    switch *StorageBackend {
    case "kubernetes.secrets":
        secret, _ := openVPNPKI.secretGetByLabels("name=" + commonName)

        if secret.Annotations["revokedAt"] != "" {
            log.Warnf("user (%s) already revoked", commonName)
            return
        }

        secret.Annotations["revokedAt"] = time.Now().Format(indexTxtDateFormat)

        _, err = openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
        if err != nil {
            return
        }

        err = openVPNPKI.indexTxtUpdate()
        if err != nil {
            return
        }

        err = openVPNPKI.updateIndexTxtOnDisk()
        if err != nil {
            return
        }

        err = openVPNPKI.GenPemCRL()
        if err != nil {
            log.Error(err)
        }

        err = openVPNPKI.updateCRLOnDisk()
    case "filesystem":

        certPath := fmt.Sprintf("%s/pki/issued/%s.crt", *EasyrsaDirPath, commonName)
        certKeyPath := fmt.Sprintf("%s/pki/private/%s.key", *EasyrsaDirPath, commonName)

        certData := fReadRaw(certPath)
        cert, _ := DecodeCert(certData)
        serialCrtPath := fmt.Sprintf("%s/pki/certs_by_serial/%X.pem", *EasyrsaDirPath, cert.SerialNumber)

        revokedCertPath := fmt.Sprintf("%s/pki/revoked/certs_by_serial/%X.crt", *EasyrsaDirPath, cert.SerialNumber)
        revokedCertKeyPath := fmt.Sprintf("%s/pki/revoked/private_by_serial/%X.key", *EasyrsaDirPath, cert.SerialNumber)

        err = fMove(certPath, revokedCertPath)
        if err != nil {
            log.Errorf("fail user revoke: %s", err.Error())
            return
        }

        err = fMove(certKeyPath, revokedCertKeyPath)
        if err != nil {
            log.Errorf("fail user revoke: %s", err.Error())
            return
        }

        _ = fDelete(serialCrtPath)

        err = openVPNPKI.indexTxtUpdate()
        if err != nil {
            return
        }


        err = openVPNPKI.GenPemCRL()
        if err != nil {
            log.Error(err)
        }
    }
    return
}


func (openVPNPKI *OpenVPNPKI) CertificateUnRevoke(commonName string) (err error) {
    switch *StorageBackend {

    case "kubernetes.secrets":
        secret, _ := openVPNPKI.secretGetByLabels("name=" + commonName)
        if err != nil {
            log.Error(err)
        }

        secret.Annotations["revokedAt"] = ""

        _, err = openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
        if err != nil {
            return
        }

        err = openVPNPKI.indexTxtUpdate()
        if err != nil {
            log.Errorf("fail user unrevoke: %s", err.Error())
            return
        }

        err = openVPNPKI.updateIndexTxtOnDisk()
        if err != nil {
            log.Errorf("fail user unrevoke: %s", err.Error())
            return
        }

        err = openVPNPKI.GenPemCRL()
        if err != nil {
            log.Error(err)
        }

        err = openVPNPKI.updateCRLOnDisk()
    case "filesystem":
        serialNumberInTxt := GetSerialNumberByUser(commonName)

        revokedCertPath := fmt.Sprintf("%s/pki/revoked/certs_by_serial/%s.crt", *EasyrsaDirPath, serialNumberInTxt)
        revokedCertKeyPath := fmt.Sprintf("%s/pki/revoked/private_by_serial/%s.key", *EasyrsaDirPath, serialNumberInTxt)

        certPath := fmt.Sprintf("%s/pki/issued/%s.crt", *EasyrsaDirPath, commonName)
        certKeyPath := fmt.Sprintf("%s/pki/private/%s.key", *EasyrsaDirPath, commonName)
        
        certData := fReadRaw(revokedCertPath)
        cert, _ := DecodeCert(certData)
        
        serialCrtPath := fmt.Sprintf("%s/pki/certs_by_serial/%X.pem", *EasyrsaDirPath, cert.SerialNumber)
        

        err = fMove(revokedCertPath, serialCrtPath)
        if err != nil {
            log.Errorf("fail user unrevoke: %s", err.Error())
            return
        }
        err = fMove(revokedCertKeyPath, certKeyPath)
        if err != nil {
            log.Errorf("fail user unrevoke: %s", err.Error())
            return
        }
        err = fCopy(serialCrtPath, certPath)
        if err != nil {
            log.Errorf("fail user unrevoke: %s", err.Error())
            return
        }

        err = openVPNPKI.indexTxtUpdate()
        if err != nil {
            log.Errorf("fail user unrevoke: %s", err.Error())
            return
        }

        err = openVPNPKI.GenPemCRL()
        if err != nil {
            log.Error(err)
        }
    }
    return
}



func (openVPNPKI *OpenVPNPKI) CertificateRotate(commonName string) (err error) {

    switch *StorageBackend {

    case "kubernetes.secrets":
        secret, _ := openVPNPKI.secretGetByLabels("name=" + commonName)
        if err != nil {
            log.Error(err)
        }
        uniqHash := strings.Replace(uuid.New().String(), "-", "", -1)
        secret.Annotations["commonName"] = "REVOKED-" + commonName + "-" + uniqHash
        secret.Labels["name"] = "REVOKED" + commonName
        secret.Labels["revokedForever"] = "true"

        _, err = openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
        if err != nil {
            return
        }

        err = openVPNPKI.BuildKeyPairClient(commonName)
        if err != nil {
            return
        }

        err = openVPNPKI.indexTxtUpdate()
        if err != nil {
            return
        }

        err = openVPNPKI.updateIndexTxtOnDisk()
        if err != nil {
            return
        }

        err = openVPNPKI.GenPemCRL()
        if err != nil {
            log.Error(err)
        }

        err = openVPNPKI.updateCRLOnDisk()

    case "filesystem":
        serialNumberInTxt := GetSerialNumberByUser(commonName)

        revokedCertPath := fmt.Sprintf("%s/pki/revoked/certs_by_serial/%s.crt", *EasyrsaDirPath, serialNumberInTxt)
        revokedCertKeyPath := fmt.Sprintf("%s/pki/revoked/private_by_serial/%s.key", *EasyrsaDirPath, serialNumberInTxt)

        indexTxtFromFile := GetIndexTxt(fRead(*IndexTxtPath))

        certData := fReadRaw(revokedCertPath)
        certPEM := bytes.NewBuffer(certData)
        cert, _ := DecodeCert(certPEM.Bytes())

        permanentRevokedCertPath := fmt.Sprintf("%s/pki/revoked/certs_by_serial/%s-del-%s.crt", *EasyrsaDirPath, cert.Subject.CommonName, serialNumberInTxt)
        permanentRevokedCertKeyPath := fmt.Sprintf("%s/pki/revoked/private_by_serial/%s-del-%s.key", *EasyrsaDirPath, cert.Subject.CommonName ,serialNumberInTxt)


        identity := string(cert.Subject.CommonName)

        if existIndex, ok := indexTxtFromFile[identity]; ok {
            existIndex.DistinguishedName = fmt.Sprintf("/CN=REVOKED-%s-%s", cert.Subject.CommonName, serialNumberInTxt)
            indexTxtFromFile[identity] = existIndex
        }
        var body []string
        for _, line := range indexTxtFromFile{
            body = append(body, fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\n", line.Flag, line.ExpirationDate, line.RevocationDate, line.SerialNumber, line.Filename, line.DistinguishedName))
        }
        err = fWrite(*EasyrsaDirPath+"/pki/index.txt", strings.Join(body, ""))
        if err != nil {
            return err
        }

        

        err = fMove(revokedCertPath, permanentRevokedCertPath)
        if err != nil {
            log.Errorf("fail user revoke: %s", err.Error())
            return
        }
        err = fMove(revokedCertKeyPath, permanentRevokedCertKeyPath)
        if err != nil {
            log.Errorf("fail user revoke: %s", err.Error())
            return
        }

        err = openVPNPKI.indexTxtUpdate()
        if err != nil {
            return
        }

        err = openVPNPKI.BuildKeyPairClient(commonName)
        if err != nil {
            return
        }


        err = openVPNPKI.GenPemCRL()
        if err != nil {
            log.Error(err)
        }
    }
    return
}

func (openVPNPKI *OpenVPNPKI) CertificateDelAfterRevoke(commonName string) (err error) {

    switch *StorageBackend {
    case "kubernetes.secrets":

        secret, _ := openVPNPKI.secretGetByLabels("name=" + commonName)
        if err != nil {
            log.Error(err)
        }
        uniqHash := strings.Replace(uuid.New().String(), "-", "", -1)
        secret.Annotations["commonName"] = "REVOKED-" + commonName + "-" + uniqHash
        secret.Labels["name"] = "REVOKED-" + commonName + "-" + uniqHash
        secret.Labels["revokedForever"] = "true"

        _, err = openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
        if err != nil {
            return
        }

        err = openVPNPKI.indexTxtUpdate()
        if err != nil {
            return
        }

        err = openVPNPKI.updateIndexTxtOnDisk()
        if err != nil {
            return
        }

        err = openVPNPKI.GenPemCRL()
        if err != nil {
            log.Error(err)
        }

        err = openVPNPKI.updateCRLOnDisk()

    case "filesystem":
        serialNumberInTxt := GetSerialNumberByUser(commonName)
        // uniqHash := strings.Replace(uuid.New().String(), "-", "", -1)

        revokedCertPath := fmt.Sprintf("%s/pki/revoked/certs_by_serial/%s.crt", *EasyrsaDirPath, serialNumberInTxt)
        revokedCertKeyPath := fmt.Sprintf("%s/pki/revoked/private_by_serial/%s.key", *EasyrsaDirPath, serialNumberInTxt)

        indexTxtFromFile := GetIndexTxt(fRead(*IndexTxtPath))

        certData := fReadRaw(revokedCertPath)
        certPEM := bytes.NewBuffer(certData)
        cert, _ := DecodeCert(certPEM.Bytes())

        permanentRevokedCertPath := fmt.Sprintf("%s/pki/revoked/certs_by_serial/%s-del-%s.crt", *EasyrsaDirPath, cert.Subject.CommonName, serialNumberInTxt)
        permanentRevokedCertKeyPath := fmt.Sprintf("%s/pki/revoked/private_by_serial/%s-del-%s.key", *EasyrsaDirPath, cert.Subject.CommonName, serialNumberInTxt)


        identity := string(cert.Subject.CommonName)

        if existIndex, ok := indexTxtFromFile[identity]; ok {
            existIndex.DistinguishedName = fmt.Sprintf("/CN=REVOKED-%s-%s", cert.Subject.CommonName, serialNumberInTxt)

            indexTxtFromFile[identity] = existIndex
        }
        var body []string
        for _, line := range indexTxtFromFile{
            body = append(body, fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\n", line.Flag, line.ExpirationDate, line.RevocationDate, line.SerialNumber, line.Filename, line.DistinguishedName))
        }
        err = fWrite(*EasyrsaDirPath+"/pki/index.txt", strings.Join(body, ""))
        if err != nil {
            return err
        }


        err = fMove(revokedCertPath, permanentRevokedCertPath)
        if err != nil {
            log.Errorf("fail user revoke: %s", err.Error())
            return
        }

        err = fMove(revokedCertKeyPath, permanentRevokedCertKeyPath)
        if err != nil {
            log.Errorf("fail user revoke: %s", err.Error())
            return
        }

        err = openVPNPKI.indexTxtUpdate()
        if err != nil {
            return
        }

        err = openVPNPKI.GenPemCRL()
        if err != nil {
            log.Error(err)
        }
    }
    return
}

func GetIndexTxt(txt string) map[string]indexTxtLine {
    myIndexTxt := make(map[string]indexTxtLine)
  

    for _, v := range IndexTxtParser(txt) {     
      a := indexTxtLine{ 
        Flag: v.Flag,
        ExpirationDate: v.ExpirationDate,
        RevocationDate: v.RevocationDate,
        SerialNumber: v.SerialNumber,
        Filename: v.Filename,
        DistinguishedName: v.DistinguishedName,
        Identity: v.Identity}
      myIndexTxt[v.Identity] = a
    }

    return myIndexTxt
}
package backend

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

// DecodeCert decode certificate from PEM to x509
func DecodeCert(certPEMBytes []byte) (cert *x509.Certificate, err error) {
	certPem, _ := pem.Decode(certPEMBytes)
	certPemBytes := certPem.Bytes

	cert, err = x509.ParseCertificate(certPemBytes)
	if err != nil {
		return
	}

	return
}

// DecodePrivKey decode private key from PEM to RSA format
func DecodePrivKey(privKey []byte) (key *rsa.PrivateKey, err error) {
	privKeyPem, _ := pem.Decode(privKey)
	key, err = x509.ParsePKCS1PrivateKey(privKeyPem.Bytes)
	if err == nil {
		return
	}

	tmp, err := x509.ParsePKCS8PrivateKey(privKeyPem.Bytes)
	if err != nil {
		err = errors.New("error parse private key")
		return
	}
	key, _ = tmp.(*rsa.PrivateKey)

	return
}

// GenPrivKey return PEM encoded private key
func GenPrivKey() (privKeyPEM *bytes.Buffer, err error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)

	//privKeyPKCS1 := x509.MarshalPKCS1PrivateKey(privKey)

	privKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return
	}

	privKeyPEM = new(bytes.Buffer)
	err = pem.Encode(privKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyPKCS8,
	})

	return
}

// GenCA return PEM encoded certificate
func GenCA(privKey *rsa.PrivateKey) (issuerPEM *bytes.Buffer, err error) {
	serialNumberRange := new(big.Int).Lsh(big.NewInt(1), 128)

	issuerSerial, err := rand.Int(rand.Reader, serialNumberRange)

	issuerTemplate := x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		SerialNumber:          issuerSerial,
		Subject: pkix.Name{
			CommonName: "ca",
		},

		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
	}
	issuerBytes, err := x509.CreateCertificate(rand.Reader, &issuerTemplate, &issuerTemplate, &privKey.PublicKey, privKey)
	if err != nil {
		return
	}

	issuerPEM = new(bytes.Buffer)
	_ = pem.Encode(issuerPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: issuerBytes,
	})

	return
}

// GenServerCert return PEM encoded certificate
func GenServerCert(privKey, caPrivKey *rsa.PrivateKey, ca *x509.Certificate, cn string) (issuerPEM *bytes.Buffer, err error) {
	serialNumberRange := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialNumberRange)

	template := x509.Certificate{
		BasicConstraintsValid: true,
		DNSNames:              []string{cn},
		SerialNumber:          serial,
		Subject: pkix.Name{
			CommonName: cn,
		},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:   time.Now(),
		NotAfter:    ca.NotAfter,
	}

	issuerBytes, err := x509.CreateCertificate(rand.Reader, &template, ca, &privKey.PublicKey, caPrivKey)
	if err != nil {
		return
	}

	issuerPEM = new(bytes.Buffer)
	_ = pem.Encode(issuerPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: issuerBytes,
	})

	return
}

// GenClientCert return PEM encoded certificate
func GenClientCert(privKey, caPrivKey *rsa.PrivateKey, ca *x509.Certificate, cn string) (issuerPEM *bytes.Buffer, err error) {
	serialNumberRange := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialNumberRange)

	template := x509.Certificate{
		BasicConstraintsValid: true,
		DNSNames:              []string{cn},
		SerialNumber:          serial,
		Subject: pkix.Name{
			CommonName: cn,
		},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		NotBefore:   time.Now(),
		NotAfter:    ca.NotAfter,
	}

	issuerBytes, err := x509.CreateCertificate(rand.Reader, &template, ca, &privKey.PublicKey, caPrivKey)
	if err != nil {
		return
	}

	issuerPEM = new(bytes.Buffer)
	_ = pem.Encode(issuerPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: issuerBytes,
	})

	return
}

// GenCRL return PEM encoded CRL
func GenCRL(certs []*RevokedCert, ca *x509.Certificate, caKey *rsa.PrivateKey) (crlPEM *bytes.Buffer, err error) {
	var revokedCertificates []pkix.RevokedCertificate

	for _, cert := range certs {
		revokedCertificates = append(revokedCertificates, pkix.RevokedCertificate{SerialNumber: cert.Cert.SerialNumber, RevocationTime: cert.RevokedTime})
	}

	revocationList := &x509.RevocationList{
		//SignatureAlgorithm: x509.SHA256WithRSA,
		RevokedCertificates: revokedCertificates,
		Number:              big.NewInt(1),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(180 * time.Hour * 24),
		//ExtraExtensions: []pkix.Extension{},
	}

	crl, err := x509.CreateRevocationList(rand.Reader, revocationList, ca, caKey)
	if err != nil {
		return nil, err
	}

	crlPEM = new(bytes.Buffer)
	err = pem.Encode(crlPEM, &pem.Block{
		Type:  "X509 CRL",
		Bytes: crl,
	})
	if err != nil {
		return
	}

	return
}

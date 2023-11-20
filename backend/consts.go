package backend

const (
	usernameRegexp       = `^([a-zA-Z0-9_.-@])+$`
	passwordMinLength    = 6
	DownloadCertsApiUrl  = "/api/data/certs/download"
	DownloadCcdApiUrl    = "/api/data/ccd/download"
	certsArchiveFileName = "certs.tar.gz"
	ccdArchiveFileName   = "ccd.tar.gz"
	indexTxtDateLayout   = "060102150405Z"
	stringDateFormat     = "2006-01-02 15:04:05"

	KubeNamespaceFilePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

	secretCA         = "openvpn-pki-ca"
	secretServer     = "openvpn-pki-server"
	secretClientTmpl = "openvpn-pki-%d"
	secretCRL        = "openvpn-pki-crl"
	secretIndexTxt   = "openvpn-pki-index-txt"
	secretDHandTA    = "openvpn-pki-dh-and-ta"
	certFileName     = "tls.crt"
	privKeyFileName  = "tls.key"

  //<year><month><day><hour><minute><second>Z
  indexTxtDateFormat = "060102150405Z"
)
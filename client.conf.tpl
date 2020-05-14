remote {{ .Host }} {{ .Port }} tcp
verb 4
client
nobind
dev tun
cipher AES-128-CBC
key-direction 1
#redirect-gateway def1
tls-client
remote-cert-tls server
# for update resolv.conf on ubuntu
#script-security 2 system
#up /etc/openvpn/update-resolv-conf
#down /etc/openvpn/update-resolv-conf
<cert>
{{ .Cert -}}
</cert>
<key>
{{ .Key -}}
</key>
<ca>
{{ .CA -}}
</ca>
<tls-auth>
{{ .TLS -}}
</tls-auth>

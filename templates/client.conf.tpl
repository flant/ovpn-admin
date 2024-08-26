{{- range $server := .Hosts }}
remote {{ $server.Host }} {{ $server.Port }} {{ $server.Protocol }}
{{- end }}

client
dev tun
proto tcp
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
verb 4
key-direction 1

<cert>
{{ .Cert -}}
</cert>
<key>
{{ .Key -}}
</key>
<ca>
{{ .CA -}}
</ca>
<tls-crypt>
{{ .TLS -}}
</tls-crypt>

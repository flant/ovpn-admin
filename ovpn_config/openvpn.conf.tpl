verb 3
tls-server
ca /etc/openvpn/easyrsa/pki/ca.crt
key /etc/openvpn/easyrsa/pki/private/server.key
cert /etc/openvpn/easyrsa/pki/issued/server.crt
dh /etc/openvpn/easyrsa/pki/dh.pem
crl-verify /etc/openvpn/easyrsa/pki/crl.pem
tls-auth /etc/openvpn/easyrsa/pki/ta.key
key-direction 0
cipher AES-128-CBC
management 127.0.0.1 8989
keepalive 10 60
persist-key
persist-tun
topology subnet
#duplicate-cn
proto udp
port 1194
dev tun0
status /tmp/openvpn-status.log
user nobody
group nogroup
push "topology subnet"
push "tun-mtu ${OPVN_VPN_MTU}"
tun-mtu ${OPVN_VPN_MTU}
push "redirect-gateway def1"
# push "dhcp-option DNS ${OVPN_DNS_SERVER_IP}"
# push "route ${OVPN_VPN_IGNORE_ROUTE_IP} ${OVPN_VPN_IGNORE_ROUTE_MASK} net_gateway"

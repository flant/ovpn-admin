#!/usr/bin/env bash
set -ex

EASY_RSA_LOC="/etc/openvpn/easyrsa"
SERVER_CERT="${EASY_RSA_LOC}/pki/issued/server.crt"

OVPN_SRV_NET=${OVPN_SERVER_NET:-10.8.0.0}
OVPN_SRV_MASK=${OVPN_SERVER_MASK:-255.255.255.0}
OVPN_SRV_PORT=${OVPN_SERVER_PORT:-1194}

cd $EASY_RSA_LOC

if [ -e "$SERVER_CERT" ]; then
  echo "Found existing certs - reusing"
else
  if [ ${OVPN_ROLE:-"master"} = "slave" ]; then
    echo "Waiting for initial sync data from master"
    while [ $(wget -q localhost/api/sync/last/try -O - | wc -m) -lt 1 ]
    do
      sleep 5
    done
  else
    echo "Generating new certs"
    easyrsa init-pki
    cp -R /usr/share/easy-rsa/* $EASY_RSA_LOC/pki
    echo "ca" | easyrsa build-ca nopass
    easyrsa build-server-full server nopass
    openvpn --genkey --secret ./pki/ta.key
  fi
fi
easyrsa gen-crl

sed -i "/# Don't delete these required lines, otherwise there will be errors/i \
# START OPENVPN RULES\n\
# NAT table rules\n\
*nat\n\
:POSTROUTING ACCEPT [0:0]\n\
-A POSTROUTING -s ${OVPN_SRV_NET}/${OVPN_SRV_MASK} -o eth0 -j MASQUERADE\n\
COMMIT\n\
# END OPENVPN RULES\n" /etc/ufw/before.rules

sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw

ufw allow ${OVPN_SRV_PORT}/tcp
ufw allow 8080/tcp
ufw disable
ufw enable

mkdir -p /dev/net
if [ ! -c /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200
fi

cp -f /etc/openvpn/setup/openvpn.conf /etc/openvpn/openvpn.conf

[ -d $EASY_RSA_LOC/pki ] && chmod 755 $EASY_RSA_LOC/pki
[ -f $EASY_RSA_LOC/pki/crl.pem ] && chmod 644 $EASY_RSA_LOC/pki/crl.pem

mkdir -p /etc/openvpn/ccd

openvpn --config /etc/openvpn/openvpn.conf --client-config-dir /etc/openvpn/ccd --port ${OVPN_SRV_PORT} --management 127.0.0.1 8989 --server ${OVPN_SRV_NET} ${OVPN_SRV_MASK}

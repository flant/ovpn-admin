#!/bin/bash
set -x
EASY_RSA_LOC="/etc/openvpn/easyrsa"
SERVER_CERT="${EASY_RSA_LOC}/pki/issued/server.crt"
cd $EASY_RSA_LOC
if [ -e "$SERVER_CERT" ]; then
  echo "found existing certs - reusing"
else
  easyrsa init-pki
  cp -R /usr/share/easy-rsa/* $EASY_RSA_LOC/pki
  echo "ca" | easyrsa build-ca nopass
  easyrsa build-server-full server nopass
  easyrsa gen-dh
  openvpn --genkey --secret ./pki/ta.key
fi
easyrsa gen-crl

iptables -t nat -A POSTROUTING -s 172.16.100.0/255.255.255.0 ! -d 172.16.100.0/255.255.255.0 -j MASQUERADE

mkdir -p /dev/net
if [ ! -c /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200
fi

cp -f /etc/openvpn/setup/openvpn.conf /etc/openvpn/openvpn.conf

[ -d $EASY_RSA_LOC/pki ] && chmod 755 $EASY_RSA_LOC/pki
[ -f $EASY_RSA_LOC/pki/crl.pem ] && chmod 644 $EASY_RSA_LOC/pki/crl.pem

mkdir -p /etc/openvpn/ccd

openvpn --config /etc/openvpn/openvpn.conf --client-config-dir /etc/openvpn/ccd


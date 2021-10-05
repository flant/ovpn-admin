#!/usr/bin/env bash

mkdir -p {easyrsa,ccd}

cd easyrsa

if [ ! -f easyrsa ]; then
  curl -sL https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz | tar -xzv --strip-components=1 -C .
fi

if [ -d pki ]; then
  exit 0
fi

./easyrsa init-pki
echo "ca" | ./easyrsa build-ca nopass
./easyrsa build-server-full server nopass
./easyrsa build-client-full client nopass

#!/usr/bin/env bash


apt-get update
apt-get install -y curl
apt-get install -y gcc-multilib libc6 libc6-dev libc6-dev-i386

curl -sL https://deb.nodesource.com/setup_14.x | bash -
apt-get install -y nodejs

PATH=$PATH:~/go/bin

go get -u github.com/gobuffalo/packr/v2/packr2

cd frontend && npm install && npm run build && cd ..

packr2

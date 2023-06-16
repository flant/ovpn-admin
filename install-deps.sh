#!/usr/bin/env bash

apt-get update
apt-get install -y curl
apt-get install -y libc6 libc6-dev libc6-dev-i386

curl -sL https://deb.nodesource.com/setup_16.x | bash -
apt-get install -y nodejs

PATH=$PATH:~/go/bin

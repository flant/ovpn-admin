#!/usr/bin/env bash

apt-get update
apt-get install -y curl
apt-get install -y libc6 libc6-dev gcc-arm-linux-gnueabi gcc-aarch64-linux-gnu

curl -sL https://deb.nodesource.com/setup_16.x | bash -
apt-get install -y nodejs

PATH=$PATH:~/go/bin

go install github.com/gobuffalo/packr/v2/packr2@latest

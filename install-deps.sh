#!/usr/bin/env bash

apt-get update
apt-get install -y npm nodejs

PATH=$PATH:~/go/bin

go get -u github.com/gobuffalo/packr/v2/packr2

cd frontend && npm install && npm run build && cd ..

packr2


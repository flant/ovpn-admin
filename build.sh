#!/bin/bash

PATH=$PATH:~/go/bin
# go get -u github.com/gobuffalo/packr/v2/packr2

cd frontend && npm install && npm run build && cd ..

packr2

CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags "-linkmode external -extldflags -static -s -w" -o openvpn-admin

packr2 clean

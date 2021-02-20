#!/bin/bash

CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags "-linkmode external -extldflags -static -s -w" -o openvpn-admin

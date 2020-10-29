#!/bin/bash

env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-extldflags "-static" -s -w' -o openvpn-admin

#!/usr/bin/env bash

PATH=$PATH:~/go/bin

cd frontend && npm install && npm run build && cd ..

CGO_ENABLED=1 GOOS=linux GOARCH=${GOARCH:-amd64} go build -a -tags netgo -ldflags "-linkmode external -extldflags -static -s -w" $@


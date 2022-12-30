#!/usr/bin/env bash

PATH=$PATH:~/go/bin

cd frontend && npm install && npm run build && cd ..

if [[ "$GOOS" == "linux" ]]; then
  if [[ "$GOARCH" == "arm" ]]; then
    CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm go build -a -tags netgo -ldflags "-linkmode external -extldflags -static -s -w" $@
  fi
  if [[ "$GOARCH" == "arm64" ]]; then
    CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -a -tags netgo -ldflags "-linkmode external -extldflags -static -s -w" $@
  fi
fi

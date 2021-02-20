FROM golang:1.14.2-buster AS backend-builder
COPY . /app
RUN cd /app && env CGO_ENABLED=./1 GOOS=linux GOARCH=amd64 go build -ldflags='-linkmode external -extldflags "-static" -s -w' -o openvpn-admin

FROM node:14.2-alpine3.11 AS frontend-builder
COPY frontend/ /app
RUN cd /app && npm install && npm run build

FROM alpine:3.13
WORKDIR /app
COPY --from=backend-builder /app/openvpn-admin /app
COPY --from=frontend-builder /app/static /app/static
COPY client.conf.tpl /app/client.conf.tpl
COPY ccd.tpl /app/ccd.tpl
RUN apk add --update bash easy-rsa  && \
    ln -s /usr/share/easy-rsa/easyrsa /usr/local/bin && \
    wget https://github.com/pashcovich/openvpn-user/releases/download/v1.0.3-rc.1/openvpn-user-linux-amd64.tar.gz -O - | tar xz -C /usr/local/bin && \
    rm -rf /tmp/* /var/tmp/* /var/cache/apk/* /var/cache/distfiles/*

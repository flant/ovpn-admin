FROM golang:1.14.2-alpine3.11 AS backend-builder
COPY . /app
#RUN apk --no-cache add build-base git gcc
RUN cd /app && env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-extldflags "-static" -s -w' -o openvpn-admin

FROM node:14.2-alpine3.11 AS frontend-builder
COPY frontend/ /app
RUN cd /app && npm install && npm run build

FROM alpine:3.11
WORKDIR /app
COPY --from=backend-builder /app/openvpn-admin /app
COPY --from=frontend-builder /app/static /app/static
COPY client.conf.tpl /app/client.conf.tpl
COPY ccd.tpl /app/ccd.tpl
RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing/" >> /etc/apk/repositories && \
    apk add --update bash easy-rsa  && \
    ln -s /usr/share/easy-rsa/easyrsa /usr/local/bin && \
    rm -rf /tmp/* /var/tmp/* /var/cache/apk/* /var/cache/distfiles/*

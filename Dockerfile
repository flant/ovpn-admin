FROM node:14.2-alpine3.11 AS frontend-builder
COPY frontend/ /app
RUN cd /app && npm install && npm run build

FROM golang:1.14.2-buster AS backend-builder
RUN go get -u github.com/gobuffalo/packr/packr2
COPY --from=frontend-builder /app/static /app/frontend/static
COPY . /app
RUN cd /app && packr2 && env CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags='-linkmode external -extldflags "-static" -s -w' -o ovpn-admin && packr2 clean

FROM alpine:3.13
WORKDIR /app
COPY --from=backend-builder /app/ovpn-admin /app
RUN apk add --update bash easy-rsa  && \
    ln -s /usr/share/easy-rsa/easyrsa /usr/local/bin && \
    wget https://github.com/pashcovich/openvpn-user/releases/download/v1.0.3/openvpn-user-linux-amd64.tar.gz -O - | tar xz -C /usr/local/bin && \
    rm -rf /tmp/* /var/tmp/* /var/cache/apk/* /var/cache/distfiles/*

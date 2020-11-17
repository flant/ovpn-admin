#!/usr/bin/env bash

./start.sh
docker-compose -p openvpn-slave -f docker-compose-slave.yaml up -d

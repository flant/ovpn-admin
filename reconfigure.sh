#!/usr/bin/env bash

if [ ! -f .env ]; then
    echo "Please create a .env file"
    exit 1
fi

source .env


envsubst < ./nginx/default.conf.tpl > ./nginx/default.conf

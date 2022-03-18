#!/bin/bash

image="node:16.13.0-alpine3.12"
uid="$(id -u $USER)"

docker run -u $uid -w /app -v $(pwd):/app $image npm i && \
docker run -u $uid -w /app -v $(pwd):/app $image npm run build

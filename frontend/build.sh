#!/bin/bash

image="node:14.2-alpine3.11"
uid="$(id -u $USER)"

docker run -u $uid -w /app -v $(pwd):/app $image npm i && \
docker run -u $uid -w /app -v $(pwd):/app $image npm run build

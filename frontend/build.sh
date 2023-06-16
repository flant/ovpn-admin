#!/bin/bash

image="node:16-alpine3.15"
uid="$(id -u $USER)"

docker run -u $uid -w /app -v $(pwd):/app $image npm i && \
docker run -u $uid -w /app -v $(pwd):/app $image npm run build

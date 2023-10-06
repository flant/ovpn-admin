#!/usr/bin/env sh

PATH=$PATH:/usr/local/bin
set -e

auth_usr=$(head -1 $1)
auth_secret=$(tail -1 $1)

if [ $common_name = $auth_usr ]; then
    curl -s --fail --data-raw 'username='${auth_usr} --data-raw 'token='${auth_secret} localhost:8080/api/auth/check
else
  echo "$(date) Authorization for user $common_name failed"
  exit 1
fi

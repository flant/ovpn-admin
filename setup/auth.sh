#!/usr/bin/env sh
source /etc/openvpn/scripts/.env
PATH=$PATH:/usr/local/bin
set -e

auth_usr=$(head -1 $1)
auth_secret=$(tail -1 $1)

if [ $common_name = $auth_usr ]; then
    curl -s --fail --data-raw 'username='${auth_usr} --data-raw 'token='${auth_secret} localhost:8080${OVPN_LISTEN_BASE_URL}api/auth/check
else
  echo "$(date) Authorization for user $common_name failed"
  exit 1
fi

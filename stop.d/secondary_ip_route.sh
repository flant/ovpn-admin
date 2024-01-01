#!/usr/bin/env bash
set -ex

default_iface=$(ip route | grep default | awk '{print $5}')
iptables -t nat -D POSTROUTING -s "$OVPN_NET_SUBNET" -o "$default_iface" -j SNAT --to-source "$OVPN_PUBLIC_IP"

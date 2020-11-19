# openvpn-admin
```
usage: openvpn-admin [<flags>]

Flags:
  --help                           Show context-sensitive help (also try --help-long and --help-man).
  --listen.host="0.0.0.0"          host(s) for openvpn-admin
  --listen.port="8080"             port for openvpn-admin
  --role="master"                  server role master or slave
  --master.host="http://127.0.0.1" url for master server
  --master.basic-auth.user=""      user for basic auth on master server url
  --master.basic-auth.password=""  password for basic auth on master server url
  --master.sync-frequency=600      master host data sync frequency in seconds.
  --master.sync-token=TOKEN        master host data sync security token
  --ovpn.host=HOST:PORT ...        host for openvpn server
  --ovpn.network="172.16.100.0/24" network for openvpn server
  --mgmt.host="127.0.0.1"          host for openvpn server mgmt interface
  --mgmt.port="8989"               port for openvpn server mgmt interface
  --easyrsa.path="/mnt/easyrsa"    path to easyrsa dir
  --easyrsa.index-path="/mnt/easyrsa/pki/index.txt"  
                                   path to easyrsa index file.
  --ccd.path="/mnt/ccd"            path to client-config-dir
  --static.path="./static"         path to static dir
  --debug                          Enable debug mode.
```
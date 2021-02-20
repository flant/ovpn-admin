# openvpn-admin
```
usage: openvpn-admin [<flags>]

Flags:
  --help                         Show context-sensitive help (also try --help-long and --help-man).
  --listen.host="0.0.0.0"        host for openvpn-admin
  --listen.port="8080"           port for openvpn-admin
  --role="master"                server role master or slave
  --master.host="http://127.0.0.1"  
                                 url for master server
  --master.basic-auth.user=""    user for basic auth on master server url
  --master.basic-auth.password=""  
                                 password for basic auth on master server url
  --master.sync-frequency=600    master host data sync frequency in seconds.
  --master.sync-token=TOKEN      master host data sync security token
  --ovpn.server=HOST:PORT ...    host(s) for openvpn server
  --ovpn.network="172.16.100.0/24"  
                                 network for openvpn server
  --mgmt=main=127.0.0.1:8989 ...  
                                 comma separated (alias=address) for openvpn servers mgmt interfaces
  --metrics.path="/metrics"      URL path for surfacing collected metrics
  --easyrsa.path="/mnt/easyrsa"  path to easyrsa dir
  --easyrsa.index-path="/mnt/easyrsa/pki/index.txt"  
                                 path to easyrsa index file.
  --ccd.path="/mnt/ccd"          path to client-config-dir
  --auth.password                Enable additional password authorization.
  --auth.db="/mnt/easyrsa/pki/users.db"  
                                 Database path fort password authorization.
  --static.path="./static"       path to static dir
  --debug                        Enable debug mode.
  --verbose                      Enable verbose mode.
  --version                      Show application version.

```
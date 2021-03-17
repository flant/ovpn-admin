# ovpn-admin

Web UI for manage and admin openvpn users

## Install

### disclaimer

Because this utility uses external calls for `bash`, `core-utils` and `easyrsa` it can work only on Linux systems

### docker

We have [docker-compose.yaml](https://github.com/flant/ovpn-admin/blob/master/docker-compose.yaml) you can just change/add values you need and start it with [start.sh](https://github.com/flant/ovpn-admin/blob/master/start.sh)

First you need to have installed
[docker](https://docs.docker.com/get-docker/)
[docker-compose](https://docs.docker.com/compose/install/)

```bash
git clone https://github.com/flant/ovpn-admin.git
cd ovpn-admin
start.sh
```

### building from source

First you need to have installed: 
[golang](https://golang.org/doc/install)
[packr2](https://github.com/gobuffalo/packr#installation)
[nodejs/npm](https://nodejs.org/en/download/package-manager/)


```bash
git clone https://github.com/flant/ovpn-admin.git
cd ovpn-admin
bootstrap.sh
build.sh
 ./ovpn-admin 
```
be sure you don't forgot  to configure all needed params

### prebuild binary (WIP)
You can use prebuild binary from [releases](https://github.com/flant/ovpn-admin/releases) page
just download tar.gz file .

## Usage

```
usage: ovpn-admin [<flags>]

Flags:
  --help                       Show context-sensitive help (also try --help-long and --help-man).
  --listen.host="0.0.0.0"      host for ovpn-admin
  --listen.port="8080"         port for ovpn-admin
  --role="master"              server role master or slave
  --master.host="http://127.0.0.1"  
                               url for master server
  --master.basic-auth.user=""  user for basic auth on master server url
  --master.basic-auth.password=""  
                               password for basic auth on master server url
  --master.sync-frequency=600  master host data sync frequency in seconds.
  --master.sync-token=TOKEN    master host data sync security token
  --ovpn.network="172.16.100.0/24"  
                               network for openvpn server
  --ovpn.server=HOST:PORT:PROTOCOL ...  
                               comma separated addresses for openvpn servers
  --mgmt=main=127.0.0.1:8989 ...  
                               comma separated (alias=address) for openvpn servers mgmt interfaces
  --metrics.path="/metrics"    URL path for surfacing collected metrics
  --easyrsa.path="./easyrsa/"  path to easyrsa dir
  --easyrsa.index-path="./easyrsa/pki/index.txt"  
                               path to easyrsa index file.
  --ccd                        Enable client-config-dir.
  --ccd.path="./ccd"           path to client-config-dir
  --auth.password              Enable additional password authorization.
  --auth.db="./easyrsa/pki/users.db"  
                               Database path fort password authorization.
  --debug                      Enable debug mode.
  --verbose                    Enable verbose mode.
  --version                    Show application version.


```

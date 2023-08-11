---
id: manager
title: Manager
---

## Configure Manager YAML File {#configure-manager-yaml-file}

The default path for the manager yaml configuration file is `/etc/dragonfly/manager.yaml` in linux,
and the default path is `$HOME/.dragonfly/config/manager.yaml` in darwin.

```yaml
# current server info used for server
server:
  # grpc server configure
  grpc:
    # listen address
    listen: 127.0.0.1
    # listen port, manager will try to listen
    # when this port is not available, manager will try next port
    port:
      start: 65003
      end: 65003
  # rest server configure
  rest:
    # stand address
    addr: :8080
  # front-end console resource path
  # publicPath: /dist

# database info used for server
database:
  # mysql configure
  mysql:
    user: dragonfly
    password: dragonfly
    host: dragonfly
    port: 3306
    dbname: manager
    migrate: true
  # tlsConfig: preferred
  # tls:
  #   # client certificate file path
  #   cert: /etc/ssl/certs/cert.pem
  #   # client key file path
  #   key: /etc/ssl/private/key.pem
  #   # ca file path
  #   ca: /etc/ssl/certs/ca.pem
  #   # whether a client verifies the server's certificate chain and host name.
  #   insecureSkipVerify: true
  # redis configure
  redis:
    password: dragonfly
    host: dragonfly
    port: 6379
    db: 0
# manager server cache
# cache:
#   # redis cache configure
#   redis:
#     # cache ttl configure
#     ttl: 30s
#   # local cache configure
#   local:
#     # lfu cache size
#     size: 10000
#     # cache ttl configure
#     ttl: 10s

# enable prometheus metrics
# metrics:
#  # manager enable metrics service
#  enable: false
#  # metrics service address
#  addr: ":8000"
#  # enable peer gauge metrics.
#  enablePeerGauge: true

# console shows log on console
console: false

# whether to enable debug level logger and enable pprof
verbose: false

# listen port for pprof, only valid when the verbose option is true
# default is -1. If it is 0, pprof will use a random port.
pprof-port: -1

# jaeger endpoint url, like: http://jaeger.dragonfly.svc:14268/api/traces
jaeger: ''
```

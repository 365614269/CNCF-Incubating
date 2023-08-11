---
id: manager
title: Manager
---

## 配置 Manager YAML 文件

Linux 环境下默认 Manager 配置路径为 `/etc/dragonfly/manager.yaml`, Darwin 环境下默认 Manager 配置路径为 `$HOME/.dragonfly/config/manager.yaml`。

```yaml
# 服务配置
server:
  # grpc 服务配置
  grpc:
    # 监听的 ip 地址
    listen: 127.0.0.1
    # 监听的端口, manager 会从 start 到 end 之间的按顺序中选择一个可用端口
    port:
      start: 65003
      end: 65003
  # rest 服务配置
  rest:
    # 标准的 rest 服务地址: ip:port, ip 不配置则默认为0.0.0.0
    addr: :8080
  # 前端控制台资源路径
  # publicPath: /dist

# 数据库配置, 当前只支持 mysql 以及 redis
database:
  # mysql 配置
  mysql:
    user: dragonfly
    password: dragonfly
    host: dragonfly
    port: 3306
    dbname: manager
    migrate: true
  # tls:
  #   # 客户端证书文件路径
  #   cert: /etc/ssl/certs/cert.pem
  #   # 客户端私钥文件路径
  #   key: /etc/ssl/private/key.pem
  #   # CA 证书文件路径
  #   ca: /etc/ssl/certs/ca.pem
  #   # 客户端是否验证服务端的证书链和 hostname
  #   insecureSkipVerify: true
  # redis 配置
  redis:
    password: dragonfly
    host: dragonfly
    port: 6379
    db: 0
# 缓存配置
# cache:
#   # redis 缓存配置
#   redis:
#     # ttl 配置
#     ttl: 30s
#   # 本地缓存配置
#   local:
#     # LFU 缓存大小
#     size: 10000
#     # ttl 配置
#     ttl: 10s

# 开启数据收集服务
# metrics:
#  # 数据服务地址
#  addr: ":8000"

# console 是否在控制台程序中显示日志
console: false

# verbose 是否使用调试级别的日志、是否启用 pprof。
verbose: false

# pprof-port pprof 监听的端口，仅在 verbose 为 true 时可用
pprof-port: -1

# jaeger 地址
# 默认使用空字符串（不配置 jaeger）, 例如: http://jaeger.dragonfly.svc:14268/api/traces
jaeger: ''
```

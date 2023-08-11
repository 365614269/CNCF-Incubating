---
id: dfdaemon
title: Dfdaemon
---

## 配置 Dfdaemon YAML 文件

Linux 环境下默认 Dfdaemon 配置路径为 `/etc/dragonfly/dfget.yaml`, Darwin 环境下默认 Dfdaemon 配置路径为 `$HOME/.dragonfly/config/dfget.yaml`。

```yaml
# daemon 存活时间, 设置为 0 秒时，daemon 将不会退出
# dfget daemon 可以由 dfget 拉起
aliveTime: 0s

# daemon gc 间隔
gcInterval: 1m0s

# daemon 工作目录
# linux 上默认目录 /usr/local/dragonfly
# macos(仅开发、测试), 默认目录是 /Users/$USER/.dragonfly
workHome: ''

# daemon 动态配置缓存目录
# linux 上默认目录 /var/cache/dragonfly
# macos(仅开发、测试), 默认目录是 /Users/$USER/.dragonfly/cache
cacheDir: ''

# daemon 日志目录
# linux 上默认目录 /var/log/dragonfly
# macos(仅开发、测试), 默认目录是 /Users/$USER/.dragonfly/logs
logDir: ''

# daemon 数据目录
# linux 上默认目录为 /var/lib/dragonfly
# macos(仅开发、测试), 默认目录是 /Users/$USER/.dragonfly/data/
dataDir: ''

# 当 daemon 退出是, 是否保存缓存数据
# 保留缓存数据在升级 daemon 的时候比较有用
# 默认为 false
keepStorage: false

# console 是否在控制台程序中显示日志
console: false

# verbose 是否使用调试级别的日志、是否启用 pprof。
verbose: false

# pprof-port pprof 监听的端口，仅在 verbose 为 true 时可用
pprof-port: -1

# jaeger 地址
# 默认使用空字符串（不配置 jaeger）, 例如: http://jaeger.dragonfly.svc:14268/api/traces
jaeger: ''

# 调度器地址
# 尽量使用同一个地区的调度器.
# daemon 将会根据 task id 来进行一致性 hash 来选择所有配置的调度器
scheduler:
  manager:
    # 通过 manager 接口动态获取 scheduler 列表
    enable: false
    # manager 服务地址
    netAddrs:
      - type: tcp
        addr: manager-service:65003
    # scheduler 列表刷新时间
    refreshInterval: 5m
  # 调度超时
  scheduleTimeout: 30s
  # 是否禁用回源，禁用回源后，在调度失败时不在 daemon 回源，直接返错
  disableAutoBackSource: false
  # 调度器地址实例
  netAddrs:
    - type: tcp
      addr: scheduler-service:8002

# 用于注册到调度器的 daemon 信息
host:
  # 服务监听地址
  listenIP: 0.0.0.0
  # 访问 IP 地址
  # 其他 daemon 可以通过这个 IP 地址连接过来
  advertiseIP: 0.0.0.0
  # 地理信息, 通过 "|" 符号分隔
  location: ''
  # 机房信息
  idc: ''
  # 安全域信息，不同安全域之间网络隔离
  securityDomain: ''
  # 网络拓扑结构，通过 "|" 符号分隔
  netTopology: ''
  # 主机名称
  # hostname: ""

# 下载服务选项
download:
  # 是否计算文件摘要，设置为 false 的话，会节省内存
  calculateDigest: true
  # 总下载限速
  totalRateLimit: 200Mi
  # 单个任务下载限速
  perPeerRateLimit: 100Mi
  # 下载 GRPC 配置
  downloadGRPC:
    # 安全选项
    security:
      insecure: true
      cacert: ''
      cert: ''
      key: ''
      tlsConfig: null
    # 下载服务监听地址，dfget 下载文件将通过该地址连接到 daemon
    # 目前是支持 unix domain socket
    unixListen:
      # linux 上默认路径为 /var/run/dfdaemon.sock
      # macos(仅开发、测试), 默认目录是 /tmp/dfdaemon.sock
      socket: /var/run/dfdaemon.sock
  # peer grpc 选项
  # peer 之间通信和下载配置
  peerGRPC:
    security:
      insecure: true
      cacert: ''
      cert: ''
      key: ''
    tcpListen:
      # 监听地址
      listen: 0.0.0.0
      # 监听端口
      # 指定固定端口，也可以指定端口范围
      port: 65000
#     port:
#       start: 65000
#       end: 65009

# 上传服务选项
upload:
  # 上传限速
  rateLimit: 100Mi
  security:
    insecure: true
    cacert: ''
    cert: ''
    key: ''
  tcpListen:
    # 监听地址
    listen: 0.0.0.0
    # 监听端口
    # 指定固定端口，也可以指定端口范围
    port: 65002
#   port:
#     start: 65020
#     end: 65029

# peer task 存储选项
storage:
  # task data 过期时间
  # 超过指定时间没有访问之后，缓存数据将会被清理
  taskExpireTime: 6h
  # storage strategy when process task data
  # io.d7y.storage.v2.simple : download file to data directory first, then copy to output path, this is default action
  #                           the download file in date directory will be the peer data for uploading to other peers
  # io.d7y.storage.v2.advance: download file directly to output path with postfix, hard link to final output,
  #                            avoid copy to output path, fast than simple strategy, but:
  #                            the output file with postfix will be the peer data for uploading to other peers
  #                            when user delete or change this file, this peer data will be corrupted
  # default is io.d7y.storage.v2.advance
  strategy: io.d7y.storage.v2.advance
  # 磁盘 GC 阈值，缓存数据超过阈值后，最旧的缓存数据将会被清理
  diskGCThreshold: 50Gi
  # 磁盘利用率 GC 阈值，磁盘利用率超过阈值后，最旧的缓存数据将会被清理
  # 例如, diskGCThresholdPercent=80, 当磁盘利用率超过 80% 的时候，会进行清理最旧的缓存数据
  diskGCThresholdPercent: 80
  # 相同 task id 的 peer task 是否复用缓存
  multiplex: true

# 代理服务配置文件，也可以使用下面的配置格式
# proxy: ""

# 代理服务详细选项
proxy:
  # 哈希 url 的时候的过滤选项
  # 例如：defaultFilter: "Expires&Signature&ns":
  #  http://localhost/xyz?Expires=111&Signature=222&ns=docker.io and http://localhost/xyz?Expires=333&Signature=999&ns=docker.io
  # 是相同的 task
  defaultFilter: 'Expires&Signature&ns'
  security:
    insecure: true
    cacert: ''
    cert: ''
    key: ''
  tcpListen:
    # 监听的网络命名空间, 例如：/proc/1/ns/net
    # 主要用在部署 kubernetes 中的时候，daemon 不使用 host network 时，监听宿主机的端口
    # 仅支持 Linux
    namespace: ''
    # 监听地址
    listen: 0.0.0.0
    # 监听端口
    port: 65001
  registryMirror:
    # 开启时，使用 header 里的 "X-Dragonfly-Registry" 替换 url 里的 host
    dynamic: true
    # 镜像中心地址
    url: https://index.docker.io
    # 忽略镜像中心证书错误
    insecure: true
    # 镜像中心证书
    certs: []
    # 是否直连镜像中心，true 的话，流量不再走 p2p
    direct: false
    # whether to use proxies to decide if dragonfly should be used
    useProxies: false

  proxies:
    # 代理镜像 blobs 信息
    - regx: blobs/sha256.*
    # 访问 some-registry 的时候，转换成 https 协议
    - regx: some-registry/
      useHTTPS: true
    # 直接透传流量，不走蜻蜓
    - regx: no-proxy-reg
      direct: true
    # 转发流量到指定地址
    - regx: some-registry
      redirect: another-registry
    # the same with url rewrite like apache ProxyPass directive
    - regx: ^http://some-registry/(.*)
      redirect: http://another-registry/$1

  hijackHTTPS:
    # https 劫持的证书和密钥
    # 建议自签 CA 并更新主机证书链
    cert: ''
    key: ''
    # 需要走蜻蜓 p2p 的流量
    hosts:
      - regx: mirror.aliyuncs.com:443 # 正则匹配
        # 忽略证书错误
        insecure: true
        # 可选：对端证书
        certs: []
  # 同时下载任务数, 0 代表不限制
  maxConcurrency: 0
  # 白名单，如果设置了，仅白名单内可以走代理，其他的都拒绝
  whiteList:
    # 主机信息
    - host: ''
      # 正则匹配
      regx:
      # 端口白名单
      ports:
      # - 80
      # - 443
```

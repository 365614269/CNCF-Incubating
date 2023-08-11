---
id: scheduler
title: Scheduler
---

## 配置 Scheduler YAML 文件

Linux 环境下默认 Scheduler 配置路径为 `/etc/dragonfly/scheduler.yaml`, Darwin 环境下默认 Scheduler 配置路径为 `$HOME/.dragonfly/config/scheduler.yaml`。

```yaml
# scheduler 服务实例配置信息
server:
  # # 服务 IP
  # ip: 127.0.0.1
  # # 服务地址
  # host: localhost
  # 服务监听端口
  port:
  # daemon 动态配置缓存目录
  # linux 上默认目录 /var/cache/dragonfly
  # macos(仅开发、测试), 默认目录是 /Users/$USER/.dragonfly/cache
  cacheDir: ''
  # daemon 日志目录
  # linux 上默认目录 /var/log/dragonfly
  # macos(仅开发、测试), 默认目录是 /Users/$USER/.dragonfly/logs
  logDir: ''

# scheduler 调度策略配置
scheduler:
  # algorithm 使用不同调度算法配置，当前默认支持 "default" 和 "ml" 两种类型
  # "default" 为基于规则的调度算法, "ml" 为基于机器学习的调度算法
  # 也支持用户 plugin 扩展的方式，值为 "plugin"
  # 并且在 dragonfly 工作目录 plugins 中添加编译好的 `d7y-scheduler-plugin-evaluator.so` 文件
  algorithm: default
  # 单个任务允许客户端回源的数量
  backSourceCount: 3
  # 调度回源重试次数限制
  retryBackSourceLimit: 5
  # 调度重试次数限制
  retryLimit: 10
  # 调度重试时间间隔
  retryInterval: 50ms
  # 数据回收策略
  gc:
    # peer 的回收间隔
    peerGCInterval: 10m
    # 不活跃的 peer 的存活时间
    peerTTL: 12h
    # task 的回收间隔
    taskGCInterval: 10m
    # 不活跃的 task 的存活时间
    taskTTL: 24h
    # host 的回收间隔
    hostGCInterval: 30m
    # 不活跃的 host 的存活时间
    hostTTL: 48h

# 动态数据配置
dynConfig:
  # 动态数据刷新间隔时间
  refreshInterval: 1m

# 实例主机信息
host:
  # 实例所在机房
  idc: ''
  # 实例网络拓扑信息
  netTopology: ''
  # 实例所在的地理位置信息
  location: ''

# manager 配置
manager:
  # manager 访问地址
  addr: manager-service:65003
  # 注册的 scheduler 集群 ID
  schedulerClusterID: 1
  # manager 心跳配置
  keepAlive:
    # 保持心跳的时间间隔
    interval: 5s

# cdn 配置
cdn:
  # 启动 cdn 作为 P2P 网络节点,
  # 如果值为 false 第一次回源请求不通过 cdn 而是通过 dfdaemon 直接回源,
  # 而且无法使用预热功能
  enable: true

# machinery 异步任务配置，配置参考 https://github.com/RichardKnop/machinery
job:
  # 启动 job 服务
  enable: true
  # global 通道 worker 数量
  globalWorkerNum: 1
  # scheduler 通道 worker 数量
  schedulerWorkerNum: 1
  # local 通道 worker 数量
  localWorkerNum: 5
  # redis 配置
  redis:
    # 服务地址
    host: ''
    # 服务端口
    port: 6379
    # 密码
    password: ''
    # broker 数据库
    brokerDB: 1
    # backend 数据库
    backendDB: 2

# 开启数据收集服务
metrics:
  # 启动数据收集服务
  enable: false
  # 数据服务地址
  addr: ':8000'
  # 开机收集 peer host 数据
  enablePeerHost: false

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

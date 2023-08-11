---
id: cdn
title: CDN
---

## 配置 CDN YAML 文件

Linux 环境下默认 CDN 配置路径为 `/etc/dragonfly/cdn.yaml`, Darwin 环境下默认 CDN 配置路径为 `$HOME/.dragonfly/config/cdn.yaml`。

```yaml
base:
  # CDN 服务监听的端口
  # 默认值：8003
  listenPort: 8003

  # CDN 提供文件下载服务的端口
  # 你需要先启动一个文件服务器，并且该文件服务器监听该下载端口。
  # 默认值：8001
  downloadPort: 8001

  # 为系统软件预留的网络带宽
  # 接收的输入格式以 G(B)/g/M(B)/m/K(B)/k/B 结尾作为单位。如果您输入一个不带单位的整数，它的单位会被认为是 B(Byte)。
  # 默认值：20 MB
  systemReservedBandwidth: 20M

  # CDN 可以使用的最大网络带宽
  # 接收的输入格式以 G(B)/g/M(B)/m/K(B)/k/B 结尾作为单位。如果您输入一个不带单位的整数，它的单位会被认为是 B(Byte)。
  # 默认值：1G
  maxBandwidth: 1G

  # CDN 暴露给 p2p 网络中的其他 peer 的 IP 地址
  # 默认值：首个非本地回环IP。
  advertiseIP:

  # CDN 请求某个 URL 失败后，不再对该 URL 发起请求的时间间隔长度
  # 换句话说，如果一个回源下载任务失败了，在这段时间里它将不会被重试。
  # 默认值：3m
  failAccessInterval: 3m

  # CDN 启动后到启动第一次垃圾回收的时间间隔
  # 默认值：6s
  gcInitialDelay: 6s

  # 进行元数据信息回收的时间间隔
  # 每隔一个该时间间隔，CDN 就会启动一次元数据信息回收。
  # 默认值：2m0s
  gcMetaInterval: 2m

  # 任务失效时间
  # 如果一个任务的信息距离上次访问过去了一个该时间间隔，该任务信息将被认为已经失效。
  # 默认值：3m0s
  taskExpireTime: 3m

  # CDN 使用的存储插件，可选[disk/hybrid]。disk 完全使用硬盘存储，hybrid 同时使用内存和硬盘进行存储。
  # 默认值：disk
  storageMode: disk

  # cdn 日志目录
  # linux 上默认目录 /var/log/dragonfly
  # macos(仅开发、测试), 默认目录是 /Users/$USER/.dragonfly/logs
  logDir: ''

  # CDN 连接的 manager，可以不指定。
  # 各项配置默认值如下。如果 addr 为空字符串，CDN将不会连接manager。
  manager:
    addr: manager-service:65003
    cdnClusterID: 1
    keepAlive:
      interval: 5s

  # 主机信息
  host:
    # 地理位置
    location: ''
    # IDC(Internet Data Center)，互联网数据中心
    idc: ''

  # 开启数据收集服务
  # metrics:
  #  # 数据服务地址
  #  addr: ":8000"

plugins:
  storagedriver:
    - name: disk
      enable: true
      config:
        baseDir: /Users/${USER_HOME}/ftp
    - name: memory
      enable: false
      config:
        baseDir: /dev/shm/dragonfly
  storagemanager:
    - name: disk
      enable: true
      config:
        gcInitialDelay: 0s
        gcInterval: 15s
        driverConfigs:
          disk:
            gcConfig:
              youngGCThreshold: 100.0GB
              fullGCThreshold: 5.0GB
              cleanRatio: 1
              intervalThreshold: 2h0m0s
    - name: hybrid
      enable: false
      config:
        gcInitialDelay: 0s
        gcInterval: 15s
        driverConfigs:
          disk:
            gcConfig:
              youngGCThreshold: 100.0GB
              fullGCThreshold: 5.0GB
              cleanRatio: 1
              intervalThreshold: 2h0m0s
          memory:
            gcConfig:
              youngGCThreshold: 100.0GB
              fullGCThreshold: 5.0GB
              cleanRatio: 3
              intervalThreshold: 2h0m0s

# console 是否在控制台程序中显示日志
console: false

# verbose 是否使用调试级别的日志、是否启用 pprof。
verbose: false

# pprof-port pprof 监听的端口，仅在 verbose 为 true 时可用
pprof-port: -1

# jaeger 地址
# 默认使用空字符串（不配置 jaeger）, 例如: http://jaeger.dragonfly.svc:14268/api/traces
jaeger: ''

# tracer 中使用的 service-name
# 默认值：dragonfly-cdn
service-name: dragonfly-cdn
```

## 配置 Nginx

<!-- markdownlint-disable -->

```nginx
worker_rlimit_nofile        100000;

events {
    use                     epoll;
    worker_connections      20480;
}

http {
    include                 mime.types;
    default_type            application/octet-stream;
    root                    /home/admin/cai/htdocs;
    sendfile                on;
    tcp_nopush              on;

    server_tokens           off;
    keepalive_timeout       5;

    client_header_timeout   1m;
    send_timeout            1m;
    client_max_body_size    3m;

    index                   index.html index.htm;
    access_log              off;
    log_not_found           off;

    gzip                    on;
    gzip_http_version       1.0;
    gzip_comp_level         6;
    gzip_min_length         1024;
    gzip_proxied            any;
    gzip_vary               on;
    gzip_disable            msie6;
    gzip_buffers            96 8k;
    gzip_types              text/xml text/plain text/css application/javascript application/x-javascript application/rss+xml application/json;

    proxy_set_header        Host $host;
    proxy_set_header        X-Real-IP $remote_addr;
    proxy_set_header        Web-Server-Type nginx;
    proxy_set_header        WL-Proxy-Client-IP $remote_addr;
    proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_redirect          off;
    proxy_buffers           128 8k;
    proxy_intercept_errors  on;

    server {
        listen              8001;
        location / {
            root /home/admin/ftp;
        }
    }
}
```

<!-- markdownlint-restore -->

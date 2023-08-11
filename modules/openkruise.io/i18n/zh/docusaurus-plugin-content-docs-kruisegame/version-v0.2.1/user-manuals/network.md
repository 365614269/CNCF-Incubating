# 网络模型
## 功能概述

如[OKG设计理念](../design-concept.md)中提到的，游戏服接入层网络是游戏开发者非常关注的问题。
非网关架构下，游戏开发者需要考虑如何暴露游戏服的外部IP端口，供玩家连接访问。
在不同场景下，往往需要不同的网络产品，而有时网络产品由云厂商提供。OKG 的 Cloud Provider & Network Plugin 源于此而诞生。
OKG 会集成不同云提供商的不同网络插件，用户可通过GameServerSet设置游戏服的网络参数，并在生成的GameServer中查看网络状态信息，极大降低了游戏服接入网络的复杂度。

## 使用示例

### Kubernetes-HostPort

OKG支持在原生Kubernetes集群使用HostPort游戏服网络，使用游戏服所在宿主机暴露外部IP及端口，转发至游戏服内部端口中。使用方式如下。

部署一个带有network的GameServerSet：

```
cat <<EOF | kubectl apply -f -
apiVersion: game.kruise.io/v1alpha1
kind: GameServerSet
metadata:
  name: gs-hostport
  namespace: default
spec:
  replicas: 1
  updateStrategy:
    rollingUpdate:
      podUpdatePolicy: InPlaceIfPossible
  network:
    networkType: Kubernetes-HostPort
    networkConf:
    #网络配置以k-v键值对的形式传入，由网络插件指定。不同网络插件有着不同的网络配置
    - name: ContainerPorts
      #ContainerPorts对应的值格式如下{containerName}:{port1}/{protocol1},{port2}/{protocol2},...
      value: "gameserver:80"
  gameServerTemplate:
    spec:
      containers:
        - image: registry.cn-hangzhou.aliyuncs.com/gs-demo/gameserver:network
          name: gameserver
EOF
```

生成的GameServer中通过networkStatus字段查看游戏服网络信息：

```shell
  networkStatus:
    createTime: "2022-11-23T10:57:01Z"
    currentNetworkState: Ready
    desiredNetworkState: Ready
    externalAddresses:
    - ip: 48.98.98.8
      ports:
      - name: gameserver-80
        port: 8211
        protocol: TCP
    internalAddresses:
    - ip: 172.16.0.8
      ports:
      - name: gameserver-80
        port: 80
        protocol: TCP
    lastTransitionTime: "2022-11-23T10:57:01Z"
    networkType: Kubernetes-HostPort
```

访问 48.98.98.8:8211 即可

### AlibabaCloud-NATGW

OKG支持阿里云下NAT网关模型，使用NATGW的外部IP与端口暴露服务，流量最终将转发至Pod之中。使用方式如下：

```shell
cat <<EOF | kubectl apply -f -
apiVersion: game.kruise.io/v1alpha1
kind: GameServerSet
metadata:
  name: gs-natgw
  namespace: default
spec:
  replicas: 1
  updateStrategy:
    rollingUpdate:
      podUpdatePolicy: InPlaceIfPossible
  network:
    networkType: AlibabaCloud-NATGW
    networkConf:
    - name: Ports
      #暴露的端口，格式如下 {port1},{port2}...
      value: "80"
    - name: Protocol
      #使用的协议，默认为TCP
      value: "TCP"
#   - name: Fixed
#     是否固定映射关系，默认不固定，pod删除后会生成新的外部IP及端口
#     value: true
  gameServerTemplate:
    spec:
      containers:
        - image: registry.cn-hangzhou.aliyuncs.com/gs-demo/gameserver:network
          name: gameserver
EOF
```

生成的GameServer中通过networkStatus字段查看游戏服网络信息：

```shell
  networkStatus:
    createTime: "2022-11-23T11:21:34Z"
    currentNetworkState: Ready
    desiredNetworkState: Ready
    externalAddresses:
    - ip: 47.97.227.137
      ports:
      - name: "80"
        port: "512"
        protocol: TCP
    internalAddresses:
    - ip: 172.16.0.189
      ports:
      - name: "80"
        port: "80"
        protocol: TCP
    lastTransitionTime: "2022-11-23T11:21:34Z"
    networkType: AlibabaCloud-NATGW
```

访问 47.97.227.137:512 即可

## 网络插件附录

当前支持的网络插件：
- Kubernetes-HostPort
- AlibabaCloud-NATGW
- AlibabaCloud-SLB
- AlibabaCloud-SLB-SharedPort

---
### Kubernetes-HostPort
#### 插件名称

`Kubernetes-HostPort`

#### Cloud Provider

Kubernetes

#### 插件说明
- Kubernetes-HostPort利用宿主机网络，通过主机上的端口转发实现游戏服对外暴露服务。宿主机需要配置公网IP，有被公网访问的能力。

- 用户在配置文件中可自定义宿主机开放的端口段（默认为8000-9000），该网络插件可以帮助用户分配管理宿主机端口，尽量避免端口冲突。

- 该插件不支持网络隔离。

#### 网络参数

ContainerPorts

- 含义：填写提供服务的容器名以及对应暴露的端口和协议
- 填写格式：containerName:port1/protocol1,port2/protocol2,...（协议需大写） 比如：`game-server:25565/TCP`
- 是否支持变更：不支持，在创建时即永久生效，随pod生命周期结束而结束

#### 插件配置

```
[kubernetes]
enable = true
[kubernetes.hostPort]
#填写宿主机可使用的空闲端口段，用于为pod分配宿主机转发端口
max_port = 9000
min_port = 8000 
```

---
### AlibabaCloud-NATGW
#### 插件名称

`AlibabaCloud-NATGW`

#### Cloud Provider

AlibabaCloud

#### 插件说明

- AlibabaCloud-NATGW 使用阿里云公网网关作为游戏服对外服务的承载实体，外网流量通过DNAT规则转发至对应的游戏服中。

- 是否支持网络隔离：否

#### 网络参数

Ports

- 含义：填写pod需要暴露的端口
- 填写格式：port1,port2,port3… 例如：80,8080,8888
- 是否支持变更：不支持

Protocol

- 含义：填写服务的网络协议
- 填写格式：例如：tcp，默认为tcp
- 是否支持变更：不支持

Fixed

- 含义：是否固定访问IP/端口。若是，即使pod删除重建，网络内外映射关系不会改变
- 填写格式：false / true
- 是否支持变更：不支持

#### 插件配置

无

---
### AlibabaCloud-SLB
#### 插件名称

`AlibabaCloud-SLB`

#### Cloud Provider

AlibabaCloud

#### 插件说明

- AlibabaCloud-SLB 使用阿里云经典四层负载均衡（SLB，又称CLB）作为对外服务的承载实体，在此模式下，不同游戏服将使用同一SLB的不同端口，此时SLB只做转发，并未均衡流量。

- 是否支持网络隔离：是

相关设计：https://github.com/openkruise/kruise-game/issues/20

#### 网络参数

SlbIds

- 含义：填写slb的id。暂只支持填写一例，未来将支持填写多例
- 填写格式：例如：lb-9zeo7prq1m25ctpfrw1m7
- 是否支持变更：暂不支持。未来将支持

PortProtocols

- 含义：pod暴露的端口及协议，支持填写多个端口/协议
- 格式：port1/protocol1,port2/protocol2,...（协议需大写）
- 是否支持变更：暂不支持。未来将支持

Fixed

- 含义：是否固定访问IP/端口。若是，即使pod删除重建，网络内外映射关系不会改变
- 填写格式：false / true
- 是否支持变更：不支持

#### 插件配置
```
[alibabacloud]
enable = true
[alibabacloud.slb]
#填写slb可使用的空闲端口段，用于为pod分配外部接入端口，范围为200
max_port = 700
min_port = 500
```

---

#### 插件名称
### AlibabaCloud-SLB-SharedPort
`AlibabaCloud-SLB-SharedPort`

#### Cloud Provider

AlibabaCloud

#### 插件说明

- AlibabaCloud-SLB-SharedPort 使用阿里云经典四层负载均衡（SLB，又称CLB）作为对外服务的承载实体。但与AlibabaCloud-SLB不同，`AlibabaCloud-SLB-SharedPort` 使用SLB同一端口转发流量，具有负载均衡的特点。
适用于游戏场景下代理（proxy）或网关等无状态网络服务。

- 是否支持网络隔离：是

#### 网络参数

SlbIds

- 含义：填写slb的id，支持填写多例
- 填写格式：例如：lb-9zeo7prq1m25ctpfrw1m7
- 是否支持变更：支持。

PortProtocols

- 含义：pod暴露的端口及协议，支持填写多个端口/协议
- 格式：port1/protocol1,port2/protocol2,...（协议需大写）
- 是否支持变更：暂不支持。未来将支持

#### 插件配置

无

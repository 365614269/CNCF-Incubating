# 网络模型
## 功能概述

如[OKG设计理念](../design-concept.md)中提到的，游戏服接入层网络是游戏开发者非常关注的问题。
非网关架构下，游戏开发者需要考虑如何暴露游戏服的外部IP端口，供玩家连接访问。
在不同场景下，往往需要不同的网络产品，而有时网络产品由云厂商提供。OKG 的 Cloud Provider & Network Plugin 源于此而诞生。
OKG 会集成不同云提供商的不同网络插件，用户可通过GameServerSet设置游戏服的网络参数，并在生成的GameServer中查看网络状态信息，极大降低了游戏服接入网络的复杂度。

## 网络插件附录

当前支持的网络插件：
- Kubernetes-HostPort
- Kubernetes-NodePort
- Kubernetes-Ingress
- AlibabaCloud-NATGW
- AlibabaCloud-SLB
- AlibabaCloud-NLB
- AlibabaCloud-EIP
- AlibabaCloud-SLB-SharedPort
- AlibabaCloud-NLB-SharedPort
- Volcengine-CLB

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

- Kubernetes-HostPort 依赖Kubernetes提供的hostPort模式。需要注意存在一些CNI插件不支持hostPort，如Terway等。



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

#### 示例说明

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

---

### Kubernetes-NodePort
#### 插件名称

`Kubernetes-NodePort`

#### Cloud Provider

Kubernetes

#### 插件说明
- Kubernetes-NodePort 利用Kubernetes NodePort 类型Service 实现游戏服对外暴露服务。宿主机需要配置公网IP，有被公网访问的能力。

- 该插件依赖节点NodePort数量限制，默认开放端口为30000-32767。若希望开放更多端口，请更改APIServer service-node-port-range 参数。

- 该插件不支持网络隔离。


#### 网络参数

PortProtocols

- 含义：pod暴露的端口及协议，支持填写多个端口/协议
- 格式：port1/protocol1,port2/protocol2,...（协议需大写）
- 是否支持变更：支持

Fixed

- 含义：是否固定访问IP/端口。若是，即使pod删除重建，网络内外映射关系不会改变
- 填写格式：false / true
- 是否支持变更：支持

AllowNotReadyContainers

- 含义：在容器原地升级时允许不断流的对应容器名称，可填写多个
- 格式：{containerName_0},{containerName_1},... 例如：sidecar
- 是否支持变更：在原地升级过程中不可变更。

#### 插件配置

无

#### 示例说明

```
cat <<EOF | kubectl apply -f -
apiVersion: game.kruise.io/v1alpha1
kind: GameServerSet
metadata:
  name: gs-nodeport
  namespace: default
spec:
  replicas: 1
  updateStrategy:
    rollingUpdate:
      podUpdatePolicy: InPlaceIfPossible
  network:
    networkType: Kubernetes-NodePort
    networkConf:
    #网络配置以k-v键值对的形式传入，由网络插件指定。不同网络插件有着不同的网络配置
    - name: PortProtocols
      value: "80"
    - name: Fixed
      value: "false"
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
    createTime: "2024-04-28T12:28:27Z"
    currentNetworkState: Ready
    desiredNetworkState: Ready
    externalAddresses:
    - ip: 120.78.78.8
      ports:
      - name: "80"
        port: 31480
        protocol: TCP
    internalAddresses:
    - ip: 172.16.0.82
      ports:
      - name: "80"
        port: 80
        protocol: TCP
    lastTransitionTime: "2024-04-28T12:28:27Z"
    networkType: Kubernetes-NodePort
```

访问 120.78.78.8:31480 即可

---

### Kubernetes-Ingress

#### 插件名称

`Kubernetes-Ingress`

#### Cloud Provider

Kubernetes

#### 插件说明

- 针对页游等需要七层网络模型的游戏场景，OKG提供了Ingress网络模型。该插件将会自动地为每个游戏服设置对应的访问路径，该路径与游戏服ID相关，每个游戏服各不相同。
- 是否支持网络隔离：否

#### 网络参数

Path

- 含义：访问路径。每个游戏服依据ID拥有各自的访问路径。
- 填写格式：将<id\>添加到原始路径(与HTTPIngressPath中Path一致)的任意位置，该插件将会生成游戏服ID对应的路径。例如，当设置路径为 /game<id\>，游戏服0对应路径为/game0，游戏服1对应路径为/game1，以此类推。
- 是否支持变更：支持

PathType

- 含义：路径类型。与HTTPIngressPath的PathType字段一致。
- 填写格式：与HTTPIngressPath的PathType字段一致。
- 是否支持变更：支持

Port

- 含义：游戏服暴露的端口值。
- 填写格式：端口数字
- 是否支持变更：支持

IngressClassName

- 含义：指定IngressClass的名称。与IngressSpec的IngressClassName字段一致。
- 填写格式：与IngressSpec的IngressClassName字段一致。
- 是否支持变更：支持

Host

- 含义：域名。每个游戏服依据ID拥有各自的访问域名。
- 填写格式：将<id\>添加域名的任意位置，该插件将会生成游戏服ID对应的域名。例如，当设置域名为 test.game<id\>.cn-hangzhou.ali.com，游戏服0对应域名为test.game0.cn-hangzhou.ali.com，游戏服1对应域名为test.game1.cn-hangzhou.ali.com，以此类推。
- 是否支持变更：支持

TlsHosts

- 含义：包含TLS证书的host列表。含义与IngressTLS的Hosts字段类似。
- 填写格式：host1,host2,... 例如，xxx.xx1.com,xxx.xx2.com
- 是否支持变更：支持

TlsSecretName

- 含义：与IngressTLS的SecretName字段一致。
- 填写格式：与IngressTLS的SecretName字段一致。
- 是否支持变更：支持

Annotation

- 含义：作为ingress对象的annotation
- 格式：key: value（注意:后有空格），例如：nginx.ingress.kubernetes.io/rewrite-target: /$2
- 是否支持变更：支持

Fixed

- 含义：是否需要保持ingress，让其不随pod的删除而删除
- 取值：true / false
- 是否支持变更：支持

_补充说明_

- 支持填写多个annotation，在networkConf中填写多个Annotation以及对应值即可，不区分填写顺序。
- 支持填写多个路径。路径、路径类型、端口按照填写顺序一一对应。当路径数目大于路径类型数目（或端口数目）时，无法找到对应关系的路径按照率先填写的路径类型（或端口）匹配。

#### 插件配置

无

#### 示例说明

GameServerSet中network字段声明如下：

```yaml
  network:
    networkConf:
    - name: IngressClassName
      value: nginx
    - name: Port
      value: "80"
    - name: Path
      value: /game<id>(/|$)(.*)
    - name: Path
      value: /test-<id>
    - name: Host
      value: test.xxx.cn-hangzhou.ali.com
    - name: PathType
      value: ImplementationSpecific
    - name: TlsHosts
      value: xxx.xx1.com,xxx.xx2.com
    - name: Annotation
      value: 'nginx.ingress.kubernetes.io/rewrite-target: /$2'
    - name: Annotation
      value: 'nginx.ingress.kubernetes.io/random: xxx'
    networkType: Kubernetes-Ingress
```

则会生成gss replicas对应数目的service与ingress对象。0号游戏服生成的ingress字段如下所示：

```yaml
spec:
  ingressClassName: nginx
  rules:
  - host: test.xxx.cn-hangzhou.ali.com
    http:
      paths:
      - backend:
          service:
            name: ing-nginx-0
            port:
              number: 80
        path: /game0(/|$)(.*)
        pathType: ImplementationSpecific
      - backend:
          service:
            name: ing-nginx-0
            port:
              number: 80
        path: /test-0
        pathType: ImplementationSpecific
  tls:
  - hosts:
    - xxx.xx1.com
    - xxx.xx2.com
status:
  loadBalancer:
    ingress:
    - ip: 47.xx.xxx.xxx
```

其他序号的游戏服只有path字段与service name不同，生成的其他参数都相同。

对应的0号GameServer的networkStatus如下：

```yaml
  networkStatus:
    createTime: "2023-04-28T14:00:30Z"
    currentNetworkState: Ready
    desiredNetworkState: Ready
    externalAddresses:
    - ip: 47.xx.xxx.xxx
      ports:
      - name: /game0(/|$)(.*)
        port: 80
        protocol: TCP
      - name: /test-0
        port: 80
        protocol: TCP
    internalAddresses:
    - ip: 10.xxx.x.xxx
      ports:
      - name: /game0(/|$)(.*)
        port: 80
        protocol: TCP
      - name: /test-0
        port: 80
        protocol: TCP
    lastTransitionTime: "2023-04-28T14:00:30Z"
    networkType: Kubernetes-Ingress
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

#### 示例说明

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
      value: "tcp"
#   - name: Fixed
#     是否固定映射关系，默认不固定，pod删除后会生成新的外部IP及端口
#     value: "true"
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

- 含义：填写slb的id。可填写多个。
- 填写格式：各个slbId用,分割。例如：lb-9zeo7prq1m25ctpfrw1m7,lb-bp1qz7h50yd3w58h2f8je,...
- 是否支持变更：支持。可追加填写SLB实例id。建议不要更换正在被使用的实例id。

PortProtocols

- 含义：pod暴露的端口及协议，支持填写多个端口/协议
- 格式：port1/protocol1,port2/protocol2,...（协议需大写）
- 是否支持变更：支持

Fixed

- 含义：是否固定访问IP/端口。若是，即使pod删除重建，网络内外映射关系不会改变
- 填写格式：false / true
- 是否支持变更：支持

AllowNotReadyContainers

- 含义：在容器原地升级时允许不断流的对应容器名称，可填写多个
- 格式：{containerName_0},{containerName_1},... 例如：sidecar
- 是否支持变更：在原地升级过程中不可变更。

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

### AlibabaCloud-NLB
#### 插件名称

`AlibabaCloud-NLB`

#### Cloud Provider

AlibabaCloud

#### 插件说明

- AlibabaCloud-NLB 使用阿里云网络型负载均衡作为对外服务的承载实体，在此模式下，不同游戏服将使用同一NLB的不同端口，此时NLB只做转发，并未均衡流量。

- 是否支持网络隔离：是

#### 网络参数

NlbIds

- 含义：填写nlb的id。可填写多个。
- 填写格式：各个nlbId用,分割。例如：nlb-ji8l844c0qzii1x6mc,nlb-26jbknebrjlejt5abu,...
- 是否支持变更：支持。可追加填写NLB实例id。建议不要更换正在被使用的实例id。

PortProtocols

- 含义：pod暴露的端口及协议，支持填写多个端口/协议
- 格式：port1/protocol1,port2/protocol2,...（协议需大写）
- 是否支持变更：支持

Fixed

- 含义：是否固定访问IP/端口。若是，即使pod删除重建，网络内外映射关系不会改变
- 填写格式：false / true
- 是否支持变更：支持

AllowNotReadyContainers

- 含义：在容器原地升级时允许不断流的对应容器名称，可填写多个
- 格式：{containerName_0},{containerName_1},... 例如：sidecar
- 是否支持变更：在原地升级过程中不可变更。

#### 插件配置
```
[alibabacloud]
enable = true
[alibabacloud.nlb]
#填写nlb可使用的空闲端口段，用于为pod分配外部接入端口，范围为500
max_port = 1500
min_port = 1000
```

#### 示例说明

```
cat <<EOF | kubectl apply -f -
apiVersion: game.kruise.io/v1alpha1
kind: GameServerSet
metadata:
  name: gs-nlb
  namespace: default
spec:
  replicas: 1
  updateStrategy:
    rollingUpdate:
      podUpdatePolicy: InPlaceIfPossible
  network:
    networkConf:
    - name: NlbIds
      value: nlb-muyo7fv6z646ygcxxx
    - name: PortProtocols
      value: "80"
    - name: Fixed
      value: "true"
    networkType: AlibabaCloud-NLB
  gameServerTemplate:
    spec:
      containers:
        - image: registry.cn-hangzhou.aliyuncs.com/gs-demo/gameserver:network
          name: gameserver
EOF
```

生成的GameServer中通过networkStatus字段查看游戏服网络信息：

```
  networkStatus:
    createTime: "2024-04-28T12:41:56Z"
    currentNetworkState: Ready
    desiredNetworkState: Ready
    externalAddresses:
    - endPoint: nlb-muyo7fv6z646ygcxxx.cn-xxx.nlb.aliyuncs.com
      ip: ""
      ports:
      - name: "80"
        port: 1047
        protocol: TCP
    internalAddresses:
    - ip: 172.16.0.1
      ports:
      - name: "80"
        port: 80
        protocol: TCP
    lastTransitionTime: "2024-04-28T12:41:56Z"
    networkType: AlibabaCloud-NLB
```

访问 nlb-muyo7fv6z646ygcxxx.cn-xxx.nlb.aliyuncs.com:1047 即可

---

### AlibabaCloud-EIP
#### 插件名称

`AlibabaCloud-EIP`

#### Cloud Provider

AlibabaCloud

#### 插件说明

- 为每个GameServer单独分配EIP
- 暴露的公网访问端口与容器中监听的端口一致，通过安全组管理
- 需要在ACK集群安装最新版本ack-extend-network-controller组件，详情请见[组件说明页](https://cs.console.aliyun.com/#/next/app-catalog/ack/incubator/ack-extend-network-controller)

#### 网络参数

ReleaseStrategy

- 含义：EIP回收策略。
- 填写格式：
    - Follow：默认值，跟随游戏服生命周期。当游戏服被删除时，EIP也将被回收。
    - Never：不删除podEIP。当不需要时需要手动删除这个podEIP。(通过kubectl delete podeip {游戏服name} -n {游戏服所在namespace})
    - 可直接配置过期时间，例如：5m30s，表示Pod删除5.5分钟后删除podEIP。支持Go类型时间表达式。
- 是否支持变更：否

PoolId

- 含义：EIP地址池ID。可为空，则不使用EIP地址池。
- 是否支持变更：否

ResourceGroupId

- 含义：EIP资源组ID。可为空，则使用默认资源组。
- 是否支持变更：否

Bandwidth

- 含义：峰值带宽。单位：Mbps。可为空，默认为5
- 是否支持变更：否

BandwidthPackageId

- 含义：要绑定已有的共享带宽包ID。可为空，则EIP不绑定共享带宽包。
- 是否支持变更：否

ChargeType

- 含义：EIP的计费方式。
- 填写格式：
    - PayByTraffic：按使用流量计费。
    - PayByBandwidth：按带宽计费，为默认值。
- 是否支持变更：否

Description

- 含义：对EIP资源的描述。
- 是否支持变更：否

#### 插件配置

无

#### 示例说明

```yaml
apiVersion: game.kruise.io/v1alpha1
kind: GameServerSet
metadata:
  name: eip-nginx
  namespace: default
spec:
  replicas: 1
  updateStrategy:
    rollingUpdate:
      podUpdatePolicy: InPlaceIfPossible
  network:
    networkType: AlibabaCloud-EIP
    networkConf:
      - name: ReleaseStrategy
        value: Never
      - name: Bandwidth
        value: "3"
      - name: ChargeType
        value: PayByTraffic
  gameServerTemplate:
    spec:
      containers:
        - image: nginx
          name: nginx
```

生成的gameserver eip-nginx-0 networkStatus字段如下所示：

```yaml
  networkStatus:
    createTime: "2023-07-17T10:10:18Z"
    currentNetworkState: Ready
    desiredNetworkState: Ready
    externalAddresses:
    - ip: 47.98.xxx.xxx
    internalAddresses:
    - ip: 192.168.1.51
    lastTransitionTime: "2023-07-17T10:10:18Z"
    networkType: AlibabaCloud-EIP
```

生成对应的podeip eip-nginx-0 如下所示：

```yaml
apiVersion: alibabacloud.com/v1beta1
kind: PodEIP
metadata:
  annotations:
    k8s.aliyun.com/eip-controller: ack-extend-network-controller
  creationTimestamp: "2023-07-17T09:58:12Z"
  finalizers:
  - podeip-controller.alibabacloud.com/finalizer
  generation: 1
  name: eip-nginx-1
  namespace: default
  resourceVersion: "41443319"
  uid: 105a9575-998e-4e17-ab91-8f2597eeb55f
spec:
  allocationID: eip-xxx
  allocationType:
    releaseStrategy: Never
    type: Auto
status:
  eipAddress: 47.98.xxx.xxx
  internetChargeType: PayByTraffic
  isp: BGP
  networkInterfaceID: eni-xxx
  podLastSeen: "2023-07-17T10:36:02Z"
  privateIPAddress: 192.168.1.51
  resourceGroupID: rg-xxx
  status: InUse
```

此外，生成的EIP资源在阿里云控制台中会以{pod namespace}/{pod name}命名，与每一个游戏服一一对应。

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

AllowNotReadyContainers

- 含义：在容器原地升级时允许不断流的对应容器名称，可填写多个
- 格式：{containerName_0},{containerName_1},... 例如：sidecar
- 是否支持变更：在原地升级过程中不可变更。

#### 插件配置

无

---
### AlibabaCloud-NLB-SharedPort

#### 插件名称

`AlibabaCloud-NLB-SharedPort`

#### Cloud Provider

AlibabaCloud

#### 插件说明

- AlibabaCloud-NLB-SharedPort 使用阿里云网络型负载均衡（NLB）作为对外服务的承载实体。其与AlibabaCloud-SLB-SharedPort作用类似。
  适用于游戏场景下代理（proxy）或网关等无状态网络服务。

- 是否支持网络隔离：是

#### 网络参数

SlbIds

- 含义：填写nlb的id，暂不支持填写多例
- 填写格式：例如：nlb-9zeo7prq1m25ctpfrw1m7
- 是否支持变更：暂不支持。

PortProtocols

- 含义：pod暴露的端口及协议，支持填写多个端口/协议
- 格式：port1/protocol1,port2/protocol2,...（协议需大写）
- 是否支持变更：暂不支持。

AllowNotReadyContainers

- 含义：在容器原地升级时允许不断流的对应容器名称，可填写多个
- 格式：{containerName_0},{containerName_1},... 例如：sidecar
- 是否支持变更：在原地升级过程中不可变更。

#### 插件配置

无

#### 示例说明

部署一个具有两个容器的GameServerSet，一个容器名为app-2048，另一个为sidecar。
指定网络参数 AllowNotReadyContainers 为 sidecar，则在sidecar原地更新时整个pod依然会提供服务，不会断流。

```yaml
apiVersion: game.kruise.io/v1alpha1
kind: GameServerSet
metadata:
  name: gss-2048-nlb
  namespace: default
spec:
  replicas: 3
  updateStrategy:
    rollingUpdate:
      maxUnavailable: 100%
      podUpdatePolicy: InPlaceIfPossible
  network:
    networkType: AlibabaCloud-NLB-SharedPort
    networkConf:
      - name: NlbIds
        value: nlb-26jbknebrjlejt5abu
      - name: PortProtocols
        value: 80/TCP
      - name: AllowNotReadyContainers
        value: sidecar
  gameServerTemplate:
    spec:
      containers:
        - image: registry.cn-beijing.aliyuncs.com/acs/2048:v1.0
          name: app-2048
          volumeMounts:
            - name: shared-dir
              mountPath: /var/www/html/js
        - image: registry.cn-beijing.aliyuncs.com/acs/2048-sidecar:v1.0
          name: sidecar
          args:
            - bash
            - -c
            - rsync -aP /app/js/* /app/scripts/ && while true; do echo 11;sleep 2; done
          volumeMounts:
            - name: shared-dir
              mountPath: /app/scripts
      volumes:
        - name: shared-dir
          emptyDir: {}
```

部署成功后，将sidecar镜像更新到v2.0版本，同时观察对应endpoint情况:
```bash
kubectl get ep -w | grep nlb-26jbknebrjlejt5abu
nlb-26jbknebrjlejt5abu      192.168.0.8:80,192.168.0.82:80,192.168.63.228:80    10m
```

等待整个更新过程结束，可以发现ep没有任何变化，说明并未进行摘流。

---

### Volcengine-CLB
#### 插件名称

`Volcengine-CLB`

#### Cloud Provider

Volcengine

#### 插件说明

- 火山引擎容器服务支持在k8s中对CLB复用的机制，不同的svc可以使用同一个CLB的不同端口。由此，Volcengine-CLB network plugin将记录各CLB对应的端口分配情况，对于指定了网络类型为Volcengine-CLB，Volcengine-CLB网络插件将会自动分配一个端口并创建一个service对象，待svc ingress字段的公网IP创建成功后，GameServer的网络处于Ready状态，该过程执行完成。

- 是否支持网络隔离：是

#### 网络参数

ClbIds

- 含义：填写clb的id，可填写多个，需要现在【火山引擎】中创建好clb。
- 填写格式：各个clbId用,分割。例如：clb-9zeo7prq1m25ctpfrw1m7,clb-bp1qz7h50yd3w58h2f8je,...
- 是否支持变更：是

PortProtocols

- 含义：pod暴露的端口及协议，支持填写多个端口/协议
- 格式：port1/protocol1,port2/protocol2,...（协议需大写）
- 是否支持变更：支持

Fixed

- 含义：是否固定访问IP/端口。若是，即使pod删除重建，网络内外映射关系不会改变
- 填写格式：false / true
- 是否支持变更：支持

AllocateLoadBalancerNodePorts

- 含义：生成的service是否分配nodeport, 仅在clb的直通模式（passthrough）下，才能设置为false
- 填写格式：true/false
- 是否支持变更：是

AllowNotReadyContainers

- 含义：在容器原地升级时允许不断流的对应容器名称，可填写多个
- 格式：{containerName_0},{containerName_1},... 例如：sidecar
- 是否支持变更：在原地升级过程中不可变更。

Annotations

- 含义：添加在service上的anno，可填写多个
- 填写格式：key1:value1,key2:value2...
- 是否支持变更：是

#### 插件配置
```
[volcengine]
enable = true
[volcengine.clb]
#填写clb可使用的空闲端口段，用于为pod分配外部接入端口，范围最大为200
max_port = 700
min_port = 500
```

#### 示例说明

```
cat <<EOF | kubectl apply -f -
apiVersion: game.kruise.io/v1alpha1
kind: GameServerSet
metadata:
  name: gss-2048-clb
  namespace: default
spec:
  replicas: 3
  updateStrategy:
    rollingUpdate:
      podUpdatePolicy: InPlaceIfPossible
  network:
    networkType: Volcengine-CLB
    networkConf:
      - name: ClbIds
        #Fill in Volcengine Cloud LoadBalancer Id here
        value: clb-xxxxx
      - name: PortProtocols
        #Fill in the exposed ports and their corresponding protocols here. 
        #If there are multiple ports, the format is as follows: {port1}/{protocol1},{port2}/{protocol2}...
        #If the protocol is not filled in, the default is TCP
        value: 80/TCP
      - name: AllocateLoadBalancerNodePorts
        # Whether the generated service is assigned nodeport.
        value: "true"
      - name: Fixed
        #Fill in here whether a fixed IP is required [optional] ; Default is false
        value: "false"
      - name: Annotations
        #Fill in the anno related to clb on the service
        #The format is as follows: {key1}:{value1},{key2}:{value2}...
        value: "key1:value1,key2:value2"
  gameServerTemplate:
    spec:
      containers:
        - image: cr-helm2-cn-beijing.cr.volces.com/kruise/2048:v1.0
          name: app-2048
          volumeMounts:
            - name: shared-dir
              mountPath: /var/www/html/js
        - image: cr-helm2-cn-beijing.cr.volces.com/kruise/2048-sidecar:v1.0
          name: sidecar
          args:
            - bash
            - -c
            - rsync -aP /app/js/* /app/scripts/ && while true; do echo 11;sleep 2; done
          volumeMounts:
            - name: shared-dir
              mountPath: /app/scripts
      volumes:
        - name: shared-dir
          emptyDir: {}
EOF
```

检查GameServer中的网络状态:

```
networkStatus:
    createTime: "2024-01-19T08:19:49Z"
    currentNetworkState: Ready
    desiredNetworkState: Ready
    externalAddresses:
    - ip: xxx.xxx.xx.xxx
      ports:
      - name: "80"
        port: 6611
        protocol: TCP
    internalAddresses:
    - ip: 172.16.200.60
      ports:
      - name: "80"
        port: 80
        protocol: TCP
    lastTransitionTime: "2024-01-19T08:19:49Z"
    networkType: Volcengine-CLB
```

---


## 获取网络信息

GameServer Network Status可以通过两种方式获取

### k8s API
调用K8s API，获取GameServer对象。该方式适用于中心组件，通常在匹配服务获取游戏服网络信息，用于路由选择等。

### DownwardAPI
通过DownwardAPI，将网络信息下沉至业务容器中，供游戏服业务容器使用

该方法的示例如下:

```yaml
apiVersion: game.kruise.io/v1alpha1
kind: GameServerSet
metadata:
  name: gs-slb
  namespace: default
spec:
  replicas: 1
  updateStrategy:
    rollingUpdate:
      podUpdatePolicy: InPlaceIfPossible
  network:
    networkType: AlibabaCloud-SLB
    networkConf:
    - name: SlbIds
      value: "xxx"
    - name: PortProtocols
      value: "xxx"
    - name: Fixed
      value: "true"
  gameServerTemplate:
    spec:
      containers:
        - image: registry.cn-hangzhou.aliyuncs.com/gs-demo/gameserver:network
          name: gameserver
          volumeMounts:
            - name: podinfo
              mountPath: /etc/podinfo
      volumes:
        - name: podinfo
          downwardAPI:
            items:
              - path: "network"
                fieldRef:
                  fieldPath: metadata.annotations['game.kruise.io/network-status']
```

字段说明:
- 在对应container字段中声明 volumeMounts，定义访问路径，此例中为 /etc/podinfo
- 在 gameServerTemplate.spec 里声明downwardAPI，文件名设置为 “network“，并指定使用 “game.kruise.io/network-status” 该annotation。注意annotation的key要使用单引号''，双引号pod将创建失败。

业务pod及容器创建成功后，在对应的/etc/podinfo路径下存在 network 文件，其中记录了序列化后的网络信息，该信息可通过json解码成对应structure，在程序获取相应字段使用。解码的sample如下（golang版本）

```go
package demo
import (
	"encoding/json"
	"github.com/openkruise/kruise-game/apis/v1alpha1"
    "os"
)

func getNetwork()  {
	network, err := os.ReadFile("/etc/podinfo/network")
	if err != nil {
		return
	}
	
	networkStatus := &v1alpha1.NetworkStatus{}

	err = json.Unmarshal(network, networkStatus)
	if err != nil {
		return
	}
	
	// 访问networkStatus各个字段
}

```

## FAQ

Q: 如何更改网络插件配置?

A: 可以通过编辑kruise-game-system命名空间下的configmap对默认参数进行更改。更改后重建kruise-game-manager，使配置生效。建议集群游戏服已使用OKG网络插件的情况下不轻易更改相应配置，应提前做好合理的网络规划。
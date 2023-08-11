# Network
## Feature overview

As mentioned in [Design concept of OpenKruiseGame](../design-concept.md), the access network of game servers is the main concern of game developers.
For a non-gateway architecture, game developers need to consider how to expose external IP addresses and ports of game servers for access by players.
Different network products are usually required for access in different scenarios, and the network products may be provided by different cloud service providers. This increases the complexity of the access network. Cloud Provider & Network Plugin of OpenKruiseGame is designed to resolve this issue.
OpenKruiseGame integrates different network plugins of different cloud service providers. You can use GameServerSet to set network parameters for game servers. Moreover, you can view network status information in the generated GameServer. This significantly reduces the complexity of the access network of game servers.

## Network plugins

OpenKruiseGame supports the following network plugins:
- Kubernetes-HostPort
- Kubernetes-Ingress
- AlibabaCloud-NATGW
- AlibabaCloud-SLB
- AlibabaCloud-EIP
- AlibabaCloud-SLB-SharedPort

---
### Kubernetes-HostPort
#### Plugin name

`Kubernetes-HostPort`

#### Cloud Provider

Kubernetes

#### Plugin description
- HostPort enables game servers to be accessed from the Internet by forwarding Internet traffic to the game servers by using the external IP address and ports exposed by the host where the game servers are located. The exposed IP address of the host must be a public IP address so that the host can be accessed from the Internet.

- In the configuration file, you can specify a custom range of available host ports. The default port range is 8000 to 9000. This network plugin can help you allocate and manage host ports to prevent port conflicts.

- This network plugin does not support network isolation.

- Kubernetes-HostPort relies on the hostPort pattern provided by Kubernetes. Note that some CNI plugins exist that do not support hostPort, such as Terway.

#### Network parameters

ContainerPorts

- Meaning: the name of the container that provides services, the ports to be exposed, and the protocols.
- Value: in the format of containerName:port1/protocol1,port2/protocol2,... The protocol names must be in uppercase letters. Example: `game-server:25565/TCP`.
- Configuration change supported or not: no. The value of this parameter is effective until the pod lifecycle ends.

#### Plugin configuration

```
[kubernetes]
enable = true
[kubernetes.hostPort]
# Specify the range of available ports of the host. Ports in this range can be used to forward Internet traffic to pods.
max_port = 9000
min_port = 8000
```

#### Example

OpenKruiseGame allows game servers to use the HostPort network in native Kubernetes clusters. The host where game servers are located exposes its external IP address and ports by using which Internet traffic is forwarded to the internal ports of the game servers. The following example shows the details:

Deploy the GameServerSet object that contains the network field.

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
    # The network configuration is specified in the form of a key-value pair. The network configuration is determined by the network plugin. Different network plugins correspond to different network configurations.
    - name: ContainerPorts
      # The value of ContainerPorts is in the following format: {containerName}:{port1}/{protocol1},{port2}/{protocol2},...
      value: "gameserver:80"
  gameServerTemplate:
    spec:
      containers:
        - image: registry.cn-hangzhou.aliyuncs.com/gs-demo/gameserver:network
          name: gameserver
EOF
```

Use the networkStatus field in the generated GameServer to view the network status information of the game server.

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

Clients can access the game server by using 48.98.98.8:8211.

---
### Kubernetes-Ingress
#### Plugin name

`Kubernetes-Ingress`

#### Cloud Provider

Kubernetes

#### Plugin description

- OKG provides the Ingress network model for games such as H5 games that require the application layer network model. This plugin will automatically set the corresponding path for each game server, which is related to the game server ID and is unique for each game server.

- This network plugin does not support network isolation.

#### Network parameters

Path

- Meaning: Access path. Each game server has its own access path based on its ID.
- Value format: Add <id\> to any position in the original path(consistent with the Path field in HTTPIngressPath), and the plugin will generate the path corresponding to the game server ID. For example, when setting the path to /game<id\>, the path for game server 0 is /game0, the path for game server 1 is /game1, and so on.
- Configuration change supported or not: yes.

PathType

- Meaning: Path type. Same as the PathType field in HTTPIngressPath.
- Value format: Same as the PathType field in HTTPIngressPath.
- Configuration change supported or not: yes.

Port

- Meaning: Port value exposed by the game server.
- Value format: port number
- Configuration change supported or not: yes.

IngressClassName

- Meaning: Specify the name of the IngressClass. Same as the IngressClassName field in IngressSpec.
- Value format: Same as the IngressClassName field in IngressSpec.
- Configuration change supported or not: yes.

Host

- Meaning: Domain name.  Each game server has its own domain based on its ID.
- Value format: Add <id\> to any position in the domain, and the plugin will generate the domain corresponding to the game server ID. For example, when setting the domain to test.game<id\>.cn-hangzhou.ali.com, the domain for game server 0 is test.game0.cn-hangzhou.ali.com, the domain for game server 1 is test.game1.cn-hangzhou.ali.com, and so on.
- Configuration change supported or not: yes.

TlsHosts

- Meaning: List of hosts containing TLS certificates. Similar to the Hosts field in IngressTLS.
- Value format: host1,host2,... For example, xxx.xx1.com,xxx.xx2.com
- Configuration change supported or not: yes.

TlsSecretName

- Meaning: Same as the SecretName field in IngressTLS.
- Value format: Same as the SecretName field in IngressTLS.
- Configuration change supported or not: yes.

Annotation

- Meaning: as an annotation of the Ingress object
- Value format: key: value (note the space after the colon), for example: nginx.ingress.kubernetes.io/rewrite-target: /$2
- Configuration change supported or not: yes.

Fixed

- Meaning: whether the ingress object is still retained when the pod is deleted
- Value format: true / false
- Configuration change supported or not: yes.

_additional explanation_

- If you want to fill in multiple annotations, you can define multiple slices named Annotation in the networkConf.
- Supports filling in multiple paths. The path, path type, and port correspond one-to-one in the order of filling. When the number of paths is greater than the number of path types(or port), non-corresponding paths will match the path type(or port) that was filled in first.


#### Plugin configuration

None

#### Example

Set GameServerSet.Spec.Network:

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
This will generate a service and an ingress object for each replica of GameServerSet. The configuration for the ingress of the 0th game server is shown below:

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

The other GameServers only have different path fields and service names, while the other generated parameters are the same.

The network status of GameServer is as follows:

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
#### Plugin name

`AlibabaCloud-NATGW`

#### Cloud Provider

AlibabaCloud

#### Plugin description

- AlibabaCloud-NATGW enables game servers to be accessed from the Internet by using an Internet NAT gateway of Alibaba Cloud. Internet traffic is forwarded to the corresponding game servers based on DNAT rules.

- This network plugin does not support network isolation.

#### Network parameters

Ports

- Meaning: the ports in the pod to be exposed.
- Value: in the format of port1,port2,port3… Example: 80,8080,8888.
- Configuration change supported or not: no.

Protocol

- Meaning: the network protocol.
- Value: an example value can be tcp. The value is tcp by default.
- Configuration change supported or not: no.

Fixed

- Meaning: whether the mapping relationship is fixed. If the mapping relationship is fixed, the mapping relationship remains unchanged even if the pod is deleted and recreated.
- Value: false or true.
- Configuration change supported or not: no.

#### Plugin configuration

None

#### Example

OpenKruiseGame supports the NAT gateway model of Alibaba Cloud. A NAT gateway exposes its external IP addresses and ports by using which Internet traffic is forwarded to pods. The following example shows the details:

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
      # The ports to be exposed. The value is in the following format: {port1},{port2}...
      value: "80"
    - name: Protocol
      # The protocol. The value is TCP by default.
      value: "tcp"
#   - name: Fixed
# Specify whether the mapping relationship is fixed. By default, the mapping relationship is not fixed, that is, a new external IP address and port are generated after the pod is deleted.
#     value: true
  gameServerTemplate:
    spec:
      containers:
        - image: registry.cn-hangzhou.aliyuncs.com/gs-demo/gameserver:network
          name: gameserver
EOF
```

Use the networkStatus field in the generated GameServer to view the network status information of the game server.

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

Clients can access the game server by using 47.97.227.137:512.

---
### AlibabaCloud-SLB
#### Plugin name

`AlibabaCloud-SLB`

#### Cloud Provider

AlibabaCloud

#### Plugin description

- AlibabaCloud-SLB enables game servers to be accessed from the Internet by using Layer 4 Classic Load Balancer (CLB) of Alibaba Cloud. CLB is a type of Server Load Balancer (SLB). AlibabaCloud-SLB uses different ports of the same CLB instance to forward Internet traffic to different game servers. The CLB instance only forwards traffic, but does not implement load balancing.

- This network plugin supports network isolation.

Related design: https://github.com/openkruise/kruise-game/issues/20

#### Network parameters

SlbIds

- Meaning: the CLB instance ID. You can fill in multiple ids.
- Value: in the format of slbId-0,slbId-1,... An example value can be "lb-9zeo7prq1m25ctpfrw1m7,lb-bp1qz7h50yd3w58h2f8je"
- Configuration change supported or not: yes. You can add new slbIds at the end. However, it is recommended not to change existing slbId that is in use.

PortProtocols

- Meaning: the ports in the pod to be exposed and the protocols. You can specify multiple ports and protocols.
- Value: in the format of port1/protocol1,port2/protocol2,... The protocol names must be in uppercase letters.
- Configuration change supported or not: yes.

Fixed

- Meaning: whether the mapping relationship is fixed. If the mapping relationship is fixed, the mapping relationship remains unchanged even if the pod is deleted and recreated.
- Value: false or true.
- Configuration change supported or not: yes.

#### Plugin configuration
```
[alibabacloud]
enable = true
[alibabacloud.slb]
# Specify the range of available ports of the CLB instance. Ports in this range can be used to forward Internet traffic to pods. In this example, the range includes 200 ports.
max_port = 700
min_port = 500
```

---
### AlibabaCloud-EIP
#### Plugin name

`AlibabaCloud-EIP`

#### Cloud Provider

AlibabaCloud

#### Plugin description

- Allocate a separate EIP for each GameServer
- The exposed public access port is consistent with the port monitored in the container, which is managed by security group.
- It is necessary to install the latest version of the ack-extend-network-controller component in the ACK cluster. For details, please refer to the [component description page](https://cs.console.aliyun.com/#/next/app-catalog/ack/incubator/ack-extend-network-controller).
#### Network parameters

ReleaseStrategy

- Meaning: Specifies the EIP release policy.
- Value:
  - Follow: follows the lifecycle of the pod that is associated with the EIP. This is the default value.
  - Never: does not release the EIP. You need to manually release the EIP when you no longer need the EIP. ( By 'kubectl delete podeip {gameserver name} -n {gameserver namespace}')
  - You can also specify the timeout period of the EIP. For example, if you set the time period to 5m30s, the EIP is released 5.5 minutes after the pod is deleted. Time expressions written in Go are supported.
- Configuration change supported or not: no.

PoolId

- Meaning: Specifies the EIP address pool. For more information. It could be nil.
- Configuration change supported or not: no.

ResourceGroupId

- Meaning: Specifies the resource group to which the EIP belongs. It could be nil.
- Configuration change supported or not: no.

Bandwidth

- Meaning: Specifies the maximum bandwidth of the EIP. Unit: Mbit/s. It could be nil. Default is 5.
- Configuration change supported or not: no.

BandwidthPackageId

- Meaning: Specifies the EIP bandwidth plan that you want to use.
- Configuration change supported or not: no.

ChargeType

- Meaning: Specifies the metering method of the EIP.
- Value：
  - PayByTraffic: Fees are charged based on data transfer.
  - PayByBandwidth: Fees are charged based on bandwidth usage.
- Configuration change supported or not: no.

Description

- Meaning: The description of EIP resource
- Configuration change supported or not: no.

#### Plugin configuration

None

#### Example

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

The network status of GameServer would be as follows:

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

The generated podeip eip-nginx-0 would be as follows：

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

In addition, the generated EIP resource will be named after {pod namespace}/{pod name} in the Alibaba Cloud console, which corresponds to each game server one by one.

---
### AlibabaCloud-SLB-SharedPort
#### Plugin name

`AlibabaCloud-SLB-SharedPort`

#### Cloud Provider

AlibabaCloud

#### Plugin description

- AlibabaCloud-SLB-SharedPort enables game servers to be accessed from the Internet by using Layer 4 CLB of Alibaba Cloud. Unlike AlibabaCloud-SLB, `AlibabaCloud-SLB-SharedPort` uses the same port of a CLB instance to forward traffic to game servers, and the CLB instance implements load balancing.
  This network plugin applies to stateless network services, such as proxy or gateway, in gaming scenarios.

- This network plugin supports network isolation.

#### Network parameters

SlbIds

- Meaning: the CLB instance IDs. You can specify multiple CLB instance IDs.
- Value: an example value can be lb-9zeo7prq1m25ctpfrw1m7.
- Configuration change supported or not: yes.

PortProtocols

- Meaning: the ports in the pod to be exposed and the protocols. You can specify multiple ports and protocols.
- Value: in the format of port1/protocol1,port2/protocol2,... The protocol names must be in uppercase letters.
- Configuration change supported or not: no. The configuration change can be supported in future.

#### Plugin configuration

None

## Access to network information

GameServer Network Status can be obtained in two ways

### k8s API
Call the K8s API and get the GameServer object. This method is applicable to the central component, usually in the matching service to get the game service network information for routing.

### DownwardAPI
Downward API to sink network information into the business container for use by the game service business container

An example of this method is as follows.

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
      value: true
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

field description:
- Declare volumeMounts in the corresponding container field, defining the access path, in this case /etc/podinfo
- Declare the downwardAPI in gameServerTemplate.spec, set the filename to "network" and specify to use "game.kruise.io/network-status "Note that the annotation key should be in single quotes '', double quotes pod will fail to be created.

After the successful creation of business pods and containers, a network file exists under the corresponding /etc/podinfo path, which records the serialized network information, which can be decoded into the corresponding structure by json and used in the program to obtain the corresponding fields. The decoded sample is as follows (golang version)

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
	
	// accessing the networkStatus fields
}

```

## FAQ

Q: How to change the network plugin configuration?

A: The default parameters can be changed by editing the configmap under the kruise-game-system namespace. After the change, rebuild kruise-game-manager to make the configuration take effect. It is recommended that the cluster game service already uses the OKG network plug-in does not easily change the corresponding configuration, and should do a reasonable network planning in advance.
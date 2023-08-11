# 游戏服热更新
## 功能概述
在游戏场景下，游戏服脚本、场景资源等属于热更文件，时常以sidecar的形式部署在pod中。
在更新这些文件时，我们往往希望不影响主程序（游戏服引擎侧）的正常运行。
然而，在原生Kubernetes集群，更新pod中任意容器都会导致pod重建，无法满足游戏热更场景。

OKG 提供的原地升级能力，可以针对性定向更新pod中某一个容器，不影响整个pod的生命周期。
如下图所示，蓝色部分为热更部分，橘色部分为非热更部分。我们将Game Script容器从版本V1更新至版本V2后，整个pod不会重建，橘色部分不受到任何影响，Game Engine正常平稳运行

![hot-update.png](/img/kruisegame/user-manuals/hot-update.png)

## 使用示例

部署带有sidecar容器的游戏服，使用GameServerSet作为游戏服负载，pod更新策略选择原地升级：

```bash
cat <<EOF | kubectl apply -f -
apiVersion: game.kruise.io/v1alpha1
kind: GameServerSet
metadata:
  name: minecraft
  namespace: default
spec:
  replicas: 3
  updateStrategy:
    rollingUpdate:
      podUpdatePolicy: InPlaceIfPossible
  gameServerTemplate:
    spec:
      containers:
        - image: registry.cn-hangzhou.aliyuncs.com/acs/minecraft-demo:1.12.2
          name: minecraft
        - image: registry.cn-hangzhou.aliyuncs.com/gs-demo/sidecar:v0.1
          name: sidecar
EOF
```

生成3个GameServer以及对应的3个Pod：

```bash
kubectl get gs
NAME          STATE   OPSSTATE   DP    UP
minecraft-0   Ready   None       0     0
minecraft-1   Ready   None       0     0
minecraft-2   Ready   None       0     0

kubectl get pod
NAME            READY   STATUS    RESTARTS   AGE
minecraft-0     2/2     Running   0          13s
minecraft-1     2/2     Running   0          13s
minecraft-2     2/2     Running   0          13s
```

当产生热更需求，我们希望只更新sidecar容器而不影响整个pod的生命周期，此时只需更新GameServerSet对应的容器镜像版本即可：

```bash
kubectl edit gss minecraft
...
      - image: registry.cn-hangzhou.aliyuncs.com/gs-demo/sidecar:v0.2
        name: sidecar
...
```

一段时间过后，发现Pod已经更新完毕，restarts次数变为1，但Age并没有减少。游戏服完成了热更新：

```bash
kubectl get pod
NAME              READY   STATUS    RESTARTS      AGE
minecraft-0       2/2     Running   1 (33s ago)   8m55s
minecraft-1       2/2     Running   1 (37s ago)   8m54s
minecraft-2       2/2     Running   1 (49s ago)   8m54s
```
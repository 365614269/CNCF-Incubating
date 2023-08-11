# 游戏服水平伸缩
## OpenKruiseGame的伸缩特性

OKG提供游戏服状态设置的能力，您可以手动/自动(服务质量功能)地设置游戏服的运维状态或删除优先级。当缩容时，GameServerSet负载会根据游戏服的状态进行缩容选择，缩容规则如下：

1）根据游戏服的opsState缩容。按顺序依次缩容opsState为`WaitToBeDeleted`、`None`、`Maintaining`的游戏服

2）当opsState相同时，按照DeletionPriority(删除优先级)缩容，优先删除DeletionPriority大的游戏服

3）当opsState与DeletionPriority都相同时，优先删除名称尾部序号较大的游戏服

### 示例

部署一个副本为5的游戏服：

```bash
cat <<EOF | kubectl apply -f -
apiVersion: game.kruise.io/v1alpha1
kind: GameServerSet
metadata:
  name: minecraft
  namespace: default
spec:
  replicas: 5
  updateStrategy:
    rollingUpdate:
      podUpdatePolicy: InPlaceIfPossible
  gameServerTemplate:
    spec:
      containers:
        - image: registry.cn-hangzhou.aliyuncs.com/acs/minecraft-demo:1.12.2
          name: minecraft
EOF
```

生成5个GameServer：

```bash
kubectl get gs
NAME          STATE   OPSSTATE   DP    UP
minecraft-0   Ready   None       0     0
minecraft-1   Ready   None       0     0
minecraft-2   Ready   None       0     0
minecraft-3   Ready   None       0     0
minecraft-4   Ready   None       0     0
```

对minecraft-2设置删除优先级为10：

```bash
kubectl edit gs minecraft-2

...
spec:
  deletionPriority: 10 #初始为0，调大到10
  opsState: None
  updatePriority: 0
...
```

手动缩容到4个副本：

```bash
kubectl scale gss minecraft --replicas=4
gameserverset.game.kruise.io/minecraft scale
```

游戏服的数目最终变为4，可以看到2号游戏服因为删除优先级最大所以被删除：

```bash
kubectl get gs
NAME          STATE      OPSSTATE   DP    UP
minecraft-0   Ready      None       0     0
minecraft-1   Ready      None       0     0
minecraft-2   Deleting   None       10    0
minecraft-3   Ready      None       0     0
minecraft-4   Ready      None       0     0

# After a while
...

kubectl get gs
NAME          STATE   OPSSTATE   DP    UP
minecraft-0   Ready   None       0     0
minecraft-1   Ready   None       0     0
minecraft-3   Ready   None       0     0
minecraft-4   Ready   None       0     0
```

设置minecraft-3的opsState为WaitToBeDeleted：

```bash
kubectl edit gs minecraft-3

...
spec:
  deletionPriority: 0 
  opsState: WaitToBeDeleted #初始为None, 将其改为WaitToBeDeleted
  updatePriority: 0
...
```

手动缩容到3个副本：

```bash
kubectl scale gss minecraft --replicas=3
gameserverset.game.kruise.io/minecraft scaled
```

游戏服的数目最终变为3，可以看到3号游戏服因为处于WaitToBeDeleted状态所以被删除：

```bash
kubectl get gs
NAME          STATE      OPSSTATE          DP    UP
minecraft-0   Ready      None              0     0
minecraft-1   Ready      None              0     0
minecraft-3   Deleting   WaitToBeDeleted   0     0
minecraft-4   Ready      None              0     0

# After a while
...

kubectl get gs
NAME          STATE   OPSSTATE   DP    UP
minecraft-0   Ready   None       0     0
minecraft-1   Ready   None       0     0
minecraft-4   Ready   None       0     0
```

手动扩容回5个副本：

```bash
kubectl scale gss minecraft --replicas=5
gameserverset.game.kruise.io/minecraft scaled
```

游戏服的数目最终变为5，此时扩容出的游戏服序号为2与3：

```bash
kubectl get gs
NAME          STATE   OPSSTATE   DP    UP
minecraft-0   Ready   None       0     0
minecraft-1   Ready   None       0     0
minecraft-2   Ready   None       0     0
minecraft-3   Ready   None       0     0
minecraft-4   Ready   None       0     0
```

## 配置游戏服的自动伸缩

GameServerSet支持HPA，您可以通过默认/自定义指标配置

### HPA示例

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: minecraft-hpa
spec:
  scaleTargetRef:
    apiVersion: game.kruise.io/v1alpha1
    kind: GameServerSet
    name: minecraft # GameServerSet对应名称
  minReplicas: 1
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 50 # 示例以cpu利用率50%为计算标准
```
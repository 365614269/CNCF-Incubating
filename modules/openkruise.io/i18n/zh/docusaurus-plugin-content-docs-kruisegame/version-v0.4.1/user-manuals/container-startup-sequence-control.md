# 容器启动顺序控制
## 功能概述

单个游戏服Pod存在多个容器的情况下，有时候会需要对容器的启动顺序有所要求。OKG提供了自定义顺序启动的功能

## 使用示例

在GameServerSet.Spec.GameServerTemplate.spec.containers 中添加 KRUISE_CONTAINER_PRIORITY 环境变量:

```
apiVersion: game.kruise.io/v1alpha1
kind: GameServerSet

# ...

spec:
  gameServerTemplate:
    spec:
      containers:
      - name: main
        # ...
      - name: sidecar
        env:
        - name: KRUISE_CONTAINER_PRIORITY
          value: "1"
    
# ...

```

- 值的范围在 [-2147483647, 2147483647]，不写默认是 0。
- 权重高的容器，会保证在权重低的容器之前启动。
- 相同权重的容器不保证启动顺序。

上述例子中游戏服启动时由于sidecar权重更高，所以先启动sidecar容器，再启动main容器
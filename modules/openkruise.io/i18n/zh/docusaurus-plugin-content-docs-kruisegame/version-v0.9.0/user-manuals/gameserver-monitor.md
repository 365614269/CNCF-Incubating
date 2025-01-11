# 游戏服监控
## 可用指标

OKG 默认透出游戏服相关 prometheus metrics，其中指标包括：

| 名称 | 描述                   | 类型      |
| --- |----------------------|---------|
| GameServersStateCount | 不同state状态下的游戏服数量     | gauge   |
| GameServersOpsStateCount | 不同opsState状态下的游戏服数量  | gauge   |
| GameServersTotal | 存在过的游戏服总数            | counter |
| GameServerSetsReplicasCount | 每个GameServerSet的副本数量 | gauge     |
| GameServerDeletionPriority | 游戏服删除优先级             | gauge     |
| GameServerUpdatePriority | 游戏服更新优先级             | gauge     |

## 监控仪表盘

### 仪表盘导入

1. 将 [grafana.json](https://github.com/openkruise/kruise-game/blob/master/config/prometheus/grafana.json) 导入至Grafana中
2. 选择数据源
3. 替换UID并完成导入

### 仪表盘说明

完成导入后的仪表盘如下所示：

<img src={require('/static/img/kruisegame/user-manuals/gra-dash.png').default} width="90%" />

从上至下，依次包含 

- 第一行：当前游戏服各个状态的数量、当前游戏服各个状态的比例饼图
- 第二行：游戏服各个状态数量变化折线图
- 第三行：游戏服删除优先级、更新优先级变化折线图（可根据左上角namespace与gsName筛选游戏服）
- 第四、五行：游戏服集合中不同状态的游戏服数量变化折线图（可根据左上角namespace与gssName筛选游戏服集合）


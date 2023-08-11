# 监控指标项

CubeFS集成了prometheus作为监控指标采集模块，可以结合具体情况开启监控指标或者配置监控面板。

## 进程相关指标

支持上报go gc stats和 mem stats, 如下

```bash
# gc相关
go_gc_duration_seconds_sum
go_gc_duration_seconds
...
# 内存分配
go_memstats_alloc_bytes
go_memstats_heap_idle_bytes
...
# 进程相关
process_resident_memory_bytes
process_start_time_seconds
process_open_fds
...
```

## Master

master模块上报的监控指标主要是关于集群内节点的健康状态，使用率，卷的统计数据等

| 指标名                                                    | 说明                               |
|--------------------------------------------------------|----------------------------------|
| cfs_master_dataNodes_count                             | 集群数据节点数量                         |
| cfs_master_dataNodes_inactive                          | 集群异常的数据节点个数                      |
| cfs_master_dataNodes_increased_GB                      | 集群2分钟内使用磁盘空间变化量                  |
| cfs_master_dataNodes_total_GB                          | 集群总的磁盘空间大小                       |
| cfs_master_dataNodes_used_GB                           | 集群已经使用的磁盘空间大小                    |
| cfs_master_disk_error{addr="xx",path="xx"}             | 集群中坏盘监控，包含异常节点IP和磁盘路径            |
| cfs_master_metaNodes_count                             | 集群总的元数据节点个数                      |
| cfs_master_metaNodes_inactive                          | 集群异常的元数据节点个数                     |
| cfs_master_metaNodes_increased_GB                      | 集群2分钟内元数据内存变化大小                  |
| cfs_master_metaNodes_total_GB                          | 集群元数据的总内存大小                      |
| cfs_master_metaNodes_used_GB                           | 集群元数据已用内存大小                      |
| cfs_master_vol_count                                   | 集群中卷的数量                          |
| cfs_master_vol_meta_count{type="dentry",volName="vol"} | 指定卷的详情，type类型：dentry,inode,dp,mp |
| cfs_master_vol_total_GB{volName="xx"}                  | 指定卷的容量带下                         |
| cfs_master_vol_usage_ratio{volName="xx"}               | 指定卷的使用率                          |
| cfs_master_vol_used_GB{volName="xx"}                   | 指定卷已用容量                          |

## MetaNode

meta节点的监控指标，可以用来监控每个卷的各种元数据操作的qps, 时延数据，如lookup, createInode，createDentry等。

| 指标名                          | 说明                                     |
|------------------------------|----------------------------------------|
| cfs_metanode_$op_count       | meta节点对应操作的请求总数，可用于计算请求qps             |
| cfs_metanode_$op_hist_bucket | meta节点对应操作请求的hist数据，可用于计算时延的95值        |
| cfs_metanode_$op_hist_count  | meta节点对应请求的总数，同cfs_metanode_$op_count  |
| cfs_metanode_$op_hist_sum    | meta节点对应操作操作请求的总耗时，与hist_count结合计算平均时延 |

## DataNode

data节点的监控指标，可以用来监控每个卷的各种数据操作的qps, 时延数据, 以及带宽，如read, write等

| 指标名                                      | 说明                                      |
|------------------------------------------|-----------------------------------------|
| cfs_dataNode_$op_count                   | data节点对应操作的请求总数，可用于计算请求qps              |
| cfs_dataNode_$op_hist_bucket             | data节点对应操作请求的hist数据，可用于计算时延的95值         |
| cfs_dataNode_$op_hist_count              | data节点对应请求的总数，同cfs_datanode_$op_count   |
| cfs_dataNode_$op_hist_sum                | data节点对应操作操作请求的总耗时，可与hist_count结合计算平均时延 |
| cfs_dataNode_dataPartitionIOBytes        | data节点读写数据总量，可用于计算指定磁盘，卷的带宽数据           |
| cfs_dataNode_dataPartitionIO_count       | data节点的io总次数，可用于计算磁盘io qps数据            |
| cfs_dataNode_dataPartitionIO_hist_bucket | data节点io操作的histogram数据，可用于计算io的95值      |
| cfs_dataNode_dataPartitionIO_hist_count  | data节点io操作的总次数，同上                       |
| cfs_dataNode_dataPartitionIO_hist_sum    | data节点io操作延时的总值，可与hist_count结合计算平均延时    |

## ObjectNode

objectNode的监控指标主要用于监控各种s3操作的请求量和耗时，如copyObject, putObject等。

| 指标名                            | 说明                                         |
|--------------------------------|:-------------------------------------------|
| cfs_objectnode_$op_count       | object节点对应操作请求的总次数，可用于计算qps                |
| cfs_objectnode_$op_hist_count  | 同上                                         |
| cfs_objectnode_$op_hist_sum    | object节点对应操作请求的总耗时，可与hist_count结合计算平均延时    |
| cfs_objectnode_$op_hist_bucket | object节点对应请求的histogram数据，可用于计算请求时延的95值，99值 |

## FuseClient

client模块的监控指标主要是用来监控与data模块，或者元数据模块的交互的请求量，耗时，缓存命中率等，如fileread, filewrite等，说明如下

| 指标名                            | 说明                                  |
|--------------------------------|-------------------------------------|
| cfs_fuseclient_$dp_count       | client对应操作的总次数，可用于计算qps             |
| cfs_fuseclient_$dp_hist_count  | 含义同上                                |
| cfs_fuseclient_$dp_hist_sum    | client对应操作的总耗时，与hist_count结合计算平均延时  |
| cfs_fuseclient_$dp_hist_bucket | client对应请求的histogram数据，用于计算请求延时的95值 |

## Blobstore

### 通用指标项

| 标签      | 说明             |
|---------|----------------|
| api     | 请求接口名，可以配置路径深度 |
| code    | 响应状态码          |
| host    | 主机名，自动获取当前主机名  |
| idc     | 配置文件配置项        |
| method  | 请求类型           |
| service | 服务名            |
| tag     | 自定义标签          |
| team    | 自定义团队名字        |

可以修改服务审计日志配置项，开启相关指标

| 配置项                    | 说明                   | 是否必须         |
|:-----------------------|:---------------------|:-------------|
| idc                    | idc名字                | 否，如果开启指标建议填写 |
| service                | 模块名字                 | 否，如果开启指标建议填写 |
| tag                    | 自定义tag，比如配置clusterid | 否，如果开启指标建议填写 |
| enable_http_method     | 是否开启状态码统计            | 否，默认关闭       |
| enable_req_length_cnt  | 是否开启请求长度统计           | 否，默认关闭       |
| enable_resp_length_cnt | 是否开启响应长度统计           | 否，默认关闭       |
| enable_resp_duration   | 是否开启请求/响应区间耗时统计      | 否，默认关闭       |
| max_api_level          | 最大api路径深度            | 否            |

```json
{
  "auditlog": {
    "metric_config": {
      "idc": "z0",
      "service": "SCHEDULER",
      "tag": "100",
      "team": "cubefs",
      "enable_http_method": true,
      "enable_req_length_cnt": true,
      "enable_resp_length_cnt": true,
      "enable_resp_duration": true,
      "max_api_level": 3
    }
  }
}
```

**service_response_code**

请求状态码指标，记录请求的api、状态码、模块名等信息，一般用来统计请求错误率、请求量之类

```bash
# TYPE service_response_code counter
service_response_code{api="scheduler.inspect.acquire",code="200",host="xxx",idc="z0",method="GET",service="SCHEDULER",tag="100",team=""} 8.766433e+06
```

**service_request_length**

请求体长度统计指标，一般用来统计请求带宽、流量

```bash
# TYPE service_request_length counter
service_request_length{api="clustermgr.chunk.report",code="200",host="xxx",idc="z0",method="POST",service="CLUSTERMGR",tag="",team=""} 27631
```

**service_response_length**

请求响应体长度长度统计指标，一般用来统计下载带宽、流量

```bash
# TYPE service_response_length counter
service_response_length{api="clustermgr.chunk.report",code="200",host="xxxx",idc="z0",method="POST",service="CLUSTERMGR",tag="",team=""} 6
```

**service_response_duration_ms**

请求响应时间统计指标，可以用来计算请求或者响应的95时延

```bash
# TYPE service_response_duration_ms histogram
service_response_duration_ms_bucket{api="clustermgr.config.get",code="200",host="xxx",idc="z0",method="GET",reqlength="",resplength="",service="CLUSTERMGR",tag="",team="",le="1"} 22
```

### Access

**blobstore_access_cache_hit_rate**

缓存命中率，status包含四类：none（命中的值为nil）、hit（命中）、miss（未命中）、expired（过期）

| 标签      | 说明                                |
|---------|-----------------------------------|
| cluster | 集群id                              |
| service | 监控组件，比如memcache，proxy等 |
| status  | 状态，none、hit、miss、expired          |

```bash
# TYPE blobstore_access_cache_hit_rate counter
blobstore_access_cache_hit_rate{cluster="100",service="memcache",status="hit"} 3.4829103e+13
blobstore_access_cache_hit_rate{cluster="100",service="proxy",status="hit"} 2.4991594e+07
```

**blobstore_access_unhealth**

失败降级指标统计

| 标签      | 说明                                    |
|---------|---------------------------------------|
| cluster | 集群id                                  |
| action  | allocate、punish、repair.msg、delete.msg |
| host    | 失败节点                                  |
| reason  | 失败原因                                  |
| module  | 降级维度，diskwith、volume、service          |

```bash
# TYPE blobstore_access_unhealth counter
blobstore_access_unhealth{action="punish",cluster="100",host="xxx",module="diskwith",reason="Timeout"} 7763
```

**blobstore_access_download**

下载失败统计指标

| 标签      | 说明                        |
|---------|---------------------------|
| cluster | 集群id                      |
| way     | 下载方式，EC读或者直接读(Direct) |

```bash
# TYPE blobstore_access_download counter
blobstore_access_download{cluster="100",way="Direct"} 37
blobstore_access_download{cluster="100",way="EC"} 3016
```

### Clustermgr

**blobstore_clusterMgr_chunk_stat_info**

chunk状态指标，统计chunk总数跟可用chunk数

| 标签        | 说明                        |
|-----------|---------------------------|
| cluster   | 集群id                      |
| idc       | idc                       |
| region    | 区域信息                      |
| is_leader | 是否为主节点                    |
| item      | TotalChunk、TotalFreeChunk |

```bash
# TYPE blobstore_clusterMgr_chunk_stat_info gauge
blobstore_clusterMgr_chunk_stat_info{cluster="100",idc="z0",is_leader="false",item="TotalChunk",region="cn-south-2"} 55619
```

**blobstore_clusterMgr_disk_stat_info**

磁盘状态指标

| 标签        | 说明                                                                           |
|-----------|------------------------------------------------------------------------------|
| cluster   | 集群id                                                                         |
| idc       | idc                                                                          |
| region    | 区域信息                                                                         |
| is_leader | 是否为主节点                                                                       |
| item      | Available、Broken、Dropped、Dropping、Expired 、Readonly、Repaired、Repairing、Total |

```bash
# TYPE blobstore_clusterMgr_disk_stat_info gauge
blobstore_clusterMgr_disk_stat_info{cluster="100",idc="z0",is_leader="false",item="Available",region="cn-south-2"} 107
```

**blobstore_clusterMgr_raft_stat**

raft状态指标

| 标签        | 说明                                        |
|-----------|-------------------------------------------|
| cluster   | 集群id                                      |
| idc       | idc                                       |
| region    | 区域信息                                      |
| is_leader | 是否为主节点                                    |
| item      | applied_index、committed_index 、peers、term |

```bash
# TYPE blobstore_clusterMgr_raft_stat gauge
blobstore_clusterMgr_raft_stat{cluster="100",is_leader="false",item="applied_index",region="cn-south-2"} 2.97061597e+08
```

**blobstore_clusterMgr_space_stat_info**

集群空间指标

| 标签        | 说明                                                                     |
|-----------|------------------------------------------------------------------------|
| cluster   | 集群id                                                                   |
| idc       | idc                                                                    |
| region    | 区域信息                                                                   |
| is_leader | 是否为主节点                                                                 |
| item      | FreeSpace 、TotalBlobNode、TotalDisk、TotalSpace、 UsedSpace、WritableSpace |

```bash
# TYPE blobstore_clusterMgr_space_stat_info gauge
blobstore_clusterMgr_space_stat_info{cluster="100",is_leader="false",item="FreeSpace",region="cn-south-2"} 1.76973072064512e+15
```

**blobstore_clusterMgr_vol_status_vol_count**

卷状态指标

| 标签        | 说明                                             |
|-----------|------------------------------------------------|
| cluster   | 集群id                                           |
| idc       | idc                                            |
| region    | 区域信息                                           |
| is_leader | 是否为主节点                                         |
| status    | active 、allocatable、idle、 lock、total、unlocking |

```bash
# TYPE blobstore_clusterMgr_vol_status_vol_count gauge
blobstore_clusterMgr_vol_status_vol_count{cluster="100",is_leader="false",region="cn-south-2",status="active"} 316
```

### BlobNode

**blobstore_blobnode_disk_stat**

磁盘状态指标

| 标签         | 说明                                  |
|------------|-------------------------------------|
| cluster_id | 集群id                                |
| idc        | idc                                 |
| disk_id    | 磁盘id                                |
| host       | 本机服务地址                              |
| rack       | 机架信息                                |
| item       | free、 reserved、total_disk_size、used |

```bash
# TYPE blobstore_blobnode_disk_stat gauge
blobstore_blobnode_disk_stat{cluster_id="100",disk_id="243",host="xxx",idc="z2",item="free",rack="testrack"} 6.47616868352e+12
```

### Scheduler

**scheduler_task_shard_cnt**

任务shard数

| 标签         | 说明                                                                    |
|------------|-----------------------------------------------------------------------|
| cluster_id | 集群id                                                                  |
| kind       | success、failed                                                        |
| task_type  | 任务类型，delete、shard_repair、balance、disk_drop、disk_repair、manual_migrate |

```bash
# TYPE scheduler_task_shard_cnt counter
scheduler_task_shard_cnt{cluster_id="100",kind="failed",task_type="delete"} 7.4912551e+07
```

**scheduler_task_reclaim**

任务重分配指标

| 标签         | 说明                                                |
|------------|---------------------------------------------------|
| cluster_id | 集群id                                              |
| kind       | success、failed                                    |
| task_type  | 任务类型，balance、disk_drop、disk_repair、manual_migrate |

```bash
# TYPE scheduler_task_reclaim counter
scheduler_task_reclaim{cluster_id="100",kind="success",task_type="balance"} 0
```

**scheduler_task_data_size**

任务迁移数据量指标，单位字节

| 标签         | 说明                                                |
|------------|---------------------------------------------------|
| cluster_id | 集群id                                              |
| kind       | success、failed                                    |
| task_type  | 任务类型，balance、disk_drop、disk_repair、manual_migrate |

```bash
# TYPE scheduler_task_data_size counter
scheduler_task_data_size{cluster_id="100",kind="success",task_type="balance"} 0
```

**scheduler_task_cnt**

任务数统计指标

| 标签          | 说明                                                |
|-------------|---------------------------------------------------|
| cluster_id  | 集群id                                              |
| kind        | success、failed                                    |
| task_type   | 任务类型，balance、disk_drop、disk_repair、manual_migrate |
| task_status | finishing、preparing、worker_doing                  |

```bash
# TYPE scheduler_task_cnt gauge
scheduler_task_cnt{cluster_id="100",kind="success",task_status="finishing",task_type="balance"} 0
```

**scheduler_task_cancel**

任务取消指标

| 标签         | 说明                                                |
|------------|---------------------------------------------------|
| cluster_id | 集群id                                              |
| kind       | success、failed                                    |
| task_type  | 任务类型，balance、disk_drop、disk_repair、manual_migrate |

```bash
# TYPE scheduler_task_cancel counter
scheduler_task_cancel{cluster_id="100",kind="success",task_type="balance"} 0
```

**scheduler_free_chunk_cnt_range**

集群空闲chunk统计

| 标签         | 说明   |
|------------|------|
| cluster_id | 集群id |
| idc        | idc  |
| rack       | 机架   |

```bash
# TYPE scheduler_free_chunk_cnt_range histogram
scheduler_free_chunk_cnt_range_bucket{cluster_id="100",idc="z0",rack="testrack",le="5"} 0
```

**kafka_topic_partition_consume_lag**

kafka消费延迟

| 标签          | 说明   |
|-------------|------|
| cluster_id  | 集群id |
| module_name | 服务名  |
| partition   | 分区   |
| topic       | 主题   |

```bash
# TYPE kafka_topic_partition_consume_lag gauge
kafka_topic_partition_consume_lag{cluster_id="100",module_name="SCHEDULER",partition="0",topic="dg_blob_delete"} 1.488541e+06
```

**kafka_topic_partition_offset**

| 标签          | 说明                    |
|-------------|-----------------------|
| cluster_id  | 集群id                  |
| module_name | 服务名                   |
| partition   | 分区                    |
| topic       | 主题                    |
| type        | consume、newest、oldest |

```bash
# TYPE kafka_topic_partition_offset gauge
kafka_topic_partition_offset{cluster_id="100",module_name="SCHEDULER",partition="0",topic="dg_blob_delete",type="consume"} 5.37820629e+08
```

### Proxy

**blobstore_proxy_volume_status**

卷状态指标

| 标签       | 说明                           |
|----------|------------------------------|
| cluster  | 集群id                         |
| idc      | idc                          |
| codemode | 卷模式                          |
| type     | total_free_size、 volume_nums |

```bash
# TYPE blobstore_proxy_volume_status gauge
blobstore_proxy_volume_status{cluster="100",codemode="EC15P12",idc="z0",service="PROXY",type="total_free_size"} 9.01538397118e+11
```

**blobstore_proxy_cache**

卷和磁盘缓存状态指标

| 标签     | 说明                                |
|----------|-------------------------------------|
| cluster  | 集群id                              |
| service  | 服务名, disk、volume                |
| name     | 缓存层，memcache、diskv、clustermgr |
| action   | 缓存值，hit、miss、expired、error   |

```bash
# TYPE blobstore_proxy_cache counter
blobstore_proxy_cache{action="hit",cluster="100",name="clustermgr",service="disk"} 6345
blobstore_proxy_cache{action="hit",cluster="100",name="memcache",service="volume"} 2.3056289e+07
blobstore_proxy_cache{action="miss",cluster="100",name="diskv",service="volume"} 230595

```

---
title: vela cluster labels add
---

add labels to managed cluster.

### Synopsis

add labels to managed cluster.

```
vela cluster labels add CLUSTER_NAME LABELS [flags]
```

### Examples

```
vela cluster labels add my-cluster project=kubevela,owner=oam-dev
```

### Options

```
  -h, --help   help for add
```

### Options inherited from parent commands

```
  -V, --verbosity Level   number for the log level verbosity
  -y, --yes               Assume yes for all user prompts
```

### SEE ALSO

* [vela cluster labels](vela_cluster_labels.md)	 - Manage Kubernetes Cluster Labels.

#### Go Back to [CLI Commands](vela.md) Homepage.


###### Auto generated by [spf13/cobra script in KubeVela](https://github.com/kubevela/kubevela/tree/master/hack/docgen).

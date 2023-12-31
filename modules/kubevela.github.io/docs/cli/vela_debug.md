---
title: vela debug
---

Debug running application.

### Synopsis

Debug running application with debug policy.

```
vela debug [flags]
```

### Examples

```
vela debug <application-name>
```

### Options

```
  -e, --env string         specify environment name for application
  -f, --focus string       specify the focus value to debug, only valid for application with workflow
  -h, --help               help for debug
  -n, --namespace string   specify the Kubernetes namespace to use
  -s, --step string        specify the step or component to debug
```

### Options inherited from parent commands

```
  -V, --verbosity Level   number for the log level verbosity
  -y, --yes               Assume yes for all user prompts
```

### SEE ALSO



#### Go Back to [CLI Commands](vela.md) Homepage.


###### Auto generated by [spf13/cobra script in KubeVela](https://github.com/kubevela/kubevela/tree/master/hack/docgen).

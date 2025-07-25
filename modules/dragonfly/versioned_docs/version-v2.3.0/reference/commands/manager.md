---
id: manager
title: Manager
slug: /reference/commands/manager/
---

Manager is a process that runs in the background
and plays the role of the brain of each subsystem cluster in Dragonfly.
It is used to manage the dynamic
configuration of each system module and provide functions
such as heartbeat keeping alive, monitoring the market, and product functions.

## Usage {#usage}

```text
manager [flags]
manager [command]
```

## Available Commands {#available-commands}

```text
completion  generate the autocompletion script for the specified shell
doc         generate documents
help        Help about any command
plugin      show plugin
version     show version
```

## Options {#options}

<!-- markdownlint-disable -->

```text
    --config string         the path of configuration file with yaml extension name, default is /etc/dragonfly/manager.yaml, it can also be set by env var: MANAGER_CONFIG
    --console               whether logger output records to the stdout
-h, --help                  help for manager
```

<!-- markdownlint-restore -->

## Log {#log}

```text
1. set option --console if you want to print logs to Terminal
2. log path: /var/log/dragonfly/manager/
```

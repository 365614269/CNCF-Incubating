---
title: "notation certificate list"
---

## notation certificate list

List certificates in the trust store

### Synopsis

List certificates in the trust store

```
notation certificate list [flags]
```

### Examples

```
# List all certificate files stored in the trust store
notation cert ls

# List all certificate files of trust store "acme-rockets"
notation cert ls --store "acme-rockets"

# List all certificate files from trust store of type "ca"
notation cert ls --type ca

# List all certificate files from trust store "wabbit-networks" of type "signingAuthority"
notation cert ls --type signingAuthority --store "wabbit-networks"
```

### Options

```
  -d, --debug          debug mode
  -h, --help           help for list
  -s, --store string   specify named store
  -t, --type string    specify trust store type, options: ca, signingAuthority
  -v, --verbose        verbose mode
```

### SEE ALSO

* [notation certificate]({{< ref "/docs/user-guides/cli-reference/notation_certificate" >}})	 - Manage certificates in trust store

###### Auto generated by spf13/cobra on 19-Sep-2023

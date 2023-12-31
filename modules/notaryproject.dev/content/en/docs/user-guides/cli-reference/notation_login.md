---
title: "notation login"
---

## notation login

Login to registry

### Synopsis

Log in to an OCI registry

```
notation login [flags] <server>
```

### Examples

```
# Login with provided username and password:
notation login -u <user> -p <password> registry.example.com

# Login using $NOTATION_USERNAME $NOTATION_PASSWORD variables:
notation login registry.example.com
```

### Options

```
  -d, --debug               debug mode
  -h, --help                help for login
      --insecure-registry   use HTTP protocol while connecting to registries. Should be used only for testing
  -p, --password string     password for registry operations (default to $NOTATION_PASSWORD if not specified)
      --password-stdin      take the password from stdin
  -u, --username string     username for registry operations (default to $NOTATION_USERNAME if not specified)
  -v, --verbose             verbose mode
```

### SEE ALSO

* [notation]({{< ref "/docs/user-guides/cli-reference/notation" >}})	 - Notation - a tool to sign and verify artifacts

###### Auto generated by spf13/cobra on 19-Sep-2023

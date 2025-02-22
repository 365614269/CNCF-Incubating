---
type: docs
title: "HTTPEndpoint spec"
linkTitle: "HTTPEndpoint"
description: "The basic spec for a Dapr HTTPEndpoint resource"
weight: 4000
aliases:
  - "/operations/httpEndpoints/"
---

The `HTTPEndpoint` is a Dapr resource that is used to enable the invocation of non-Dapr endpoints from a Dapr application.

{{% alert title="Note" color="primary" %}}
Any HTTPEndpoint resource can be restricted to a particular [namepsace]({{< ref isolation-concept.md >}}) and restricted access through scopes to any particular set of applications.
{{% /alert %}}

## Format

```yaml
apiVersion: dapr.io/v1alpha1
kind: HTTPEndpoint
metadata:
  name: <NAME>  
spec:
  baseUrl: <REPLACE-WITH-BASEURL> # Required. Use "http://" or "https://" prefix.
  headers: # Optional
  - name: <REPLACE-WITH-A-HEADER-NAME>
    value: <REPLACE-WITH-A-HEADER-VALUE>
  - name: <REPLACE-WITH-A-HEADER-NAME>
    secretKeyRef:
      name: <REPLACE-WITH-SECRET-NAME>
      key: <REPLACE-WITH-SECRET-KEY>
  clientTLS:
    rootCA:
      secretKeyRef:
        name: <REPLACE-WITH-SECRET-NAME>
        key: <REPLACE-WITH-SECRET-KEY>
    certificate:
      secretKeyRef:
        name: <REPLACE-WITH-SECRET-NAME>
        key: <REPLACE-WITH-SECRET-KEY>
    privateKey:
      secretKeyRef:
        name: <REPLACE-WITH-SECRET-NAME>
        key: <REPLACE-WITH-SECRET-KEY>
scopes: # Optional
  - <REPLACE-WITH-SCOPED-APPIDS>
auth: # Optional
  secretStore: <REPLACE-WITH-SECRETSTORE>
```

## Spec fields

| Field              | Required | Details | Example |
|--------------------|:--------:|---------|---------|
| baseUrl            | Y        | Base URL of the non-Dapr endpoint | `"https://api.github.com"`, `"http://api.github.com"`
| headers            | N        | HTTP request headers for service invocation | `name: "Accept-Language" value: "en-US"` <br/> `name: "Authorization" secretKeyRef.name: "my-secret" secretKeyRef.key: "myGithubToken" `
| clientTLS          | N        | Enables TLS authentication to an endpoint with any standard combination of root certificate, client certificate and private key

## Related links

[Learn how to invoke non-Dapr endpoints.]({{< ref howto-invoke-non-dapr-endpoints.md >}})

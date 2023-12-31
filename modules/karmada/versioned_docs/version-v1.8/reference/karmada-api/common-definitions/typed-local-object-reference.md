---
api_metadata:
  apiVersion: ""
  import: "k8s.io/api/core/v1"
  kind: "TypedLocalObjectReference"
content_type: "api_reference"
description: "TypedLocalObjectReference contains enough information to let you locate the typed referenced object inside the same namespace."
title: "TypedLocalObjectReference"
weight: 9
auto_generated: true
---

[//]: # (The file is auto-generated from the Go source code of the component using a generic generator,)
[//]: # (which is forked from [reference-docs](https://github.com/kubernetes-sigs/reference-docs.)
[//]: # (To update the reference content, please follow the `reference-api.sh`.)

`import "k8s.io/api/core/v1"`

TypedLocalObjectReference contains enough information to let you locate the typed referenced object inside the same namespace.

<hr/>

- **kind** (string), required

  Kind is the type of resource being referenced

- **name** (string), required

  Name is the name of resource being referenced

- **apiGroup** (string)

  APIGroup is the group for the resource being referenced. If APIGroup is not specified, the specified Kind must be in the core API group. For any other third-party types, APIGroup is required.


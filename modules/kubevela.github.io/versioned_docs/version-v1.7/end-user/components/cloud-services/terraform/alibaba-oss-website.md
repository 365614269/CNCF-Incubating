---
title:  Alibaba Cloud OSS-WEBSITE
---

## Description

Alibaba Cloud OSS static webstie bucket.

## Examples

```yaml
apiVersion: core.oam.dev/v1beta1
kind: Application
metadata:
  name: alibaba-cloud-oss-webstie
spec:
  components:
    - name: oss-website-example
      type: alibaba-oss-website
      properties:
        acl: public-read
        bucket: oss-website-example
        index_document: index.html
        error_document: 404.html
        writeConnectionSecretToRef:
          name: oss-website-conn
```

## Specification

### Properties

 Name | Description | Type | Required | Default 
 ------------ | ------------- | ------------- | ------------- | ------------- 
 acl | OSS bucket ACL, supported 'private', 'public-read', 'public-read-write'. | string | false |  
 bucket | OSS bucket name. | string | false |  
 error_document | OSS bucket static website error document. | string | false |  
 index_document | OSS bucket static website index document. | string | false |  
 writeConnectionSecretToRef | The secret which the cloud resource connection will be written to. | [writeConnectionSecretToRef](#writeConnectionSecretToRef) | false |  


#### writeConnectionSecretToRef

 Name | Description | Type | Required | Default 
 ------------ | ------------- | ------------- | ------------- | ------------- 
 name | The secret name which the cloud resource connection will be written to. | string | true |  
 namespace | The secret namespace which the cloud resource connection will be written to. | string | false |  


### Outputs

If `writeConnectionSecretToRef` is set, a secret will be generated with these keys as below:

 Name | Description 
 ------------ | ------------- 
 BUCKET_NAME | 
 EXTRANET_ENDPOINT | OSS bucket external endpoint
 INTRANET_ENDPOINT | OSS bucket internal endpoint

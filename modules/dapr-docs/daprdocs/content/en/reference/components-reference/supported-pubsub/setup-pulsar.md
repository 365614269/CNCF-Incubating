---
type: docs
title: "Pulsar"
linkTitle: "Pulsar"
description: "Detailed documentation on the Pulsar pubsub component"
aliases:
  - "/operations/components/setup-pubsub/supported-pubsub/setup-pulsar/"
---

## Component format

To set up Apache Pulsar pub/sub, create a component of type `pubsub.pulsar`. See the [pub/sub broker component file]({{< ref setup-pubsub.md >}}) to learn how ConsumerID is automatically generated. Read the [How-to: Publish and Subscribe guide]({{< ref "howto-publish-subscribe.md#step-1-setup-the-pubsub-component" >}}) on how to create and apply a pub/sub configuration. 

For more information on Apache Pulsar, [read the official docs](https://pulsar.apache.org/docs/en/concepts-overview/).

```yaml
apiVersion: dapr.io/v1alpha1
kind: Component
metadata:
  name: pulsar-pubsub
spec:
  type: pubsub.pulsar
  version: v1
  metadata:
  - name: host
    value: "localhost:6650"
  - name: enableTLS
    value: "false"
  - name: tenant
    value: "public"
  - name: token
    value: "eyJrZXlJZCI6InB1bHNhci1wajU0cXd3ZHB6NGIiLCJhbGciOiJIUzI1NiJ9.eyJzd"
  - name: consumerID
    value: "channel1"
  - name: namespace
    value: "default"
  - name: persistent
    value: "true"
  - name: disableBatching
    value: "false"
  - name: receiverQueueSize
    value: "1000"
  - name: <topic-name>.jsonschema # sets a json schema validation for the configured topic
    value: |
      {
        "type": "record",
        "name": "Example",
        "namespace": "test",
        "fields": [
          {"name": "ID","type": "int"},
          {"name": "Name","type": "string"}
        ]
      }
  - name: <topic-name>.avroschema # sets an avro schema validation for the configured topic
    value: |
      {
        "type": "record",
        "name": "Example",
        "namespace": "test",
        "fields": [
          {"name": "ID","type": "int"},
          {"name": "Name","type": "string"}
        ]
      }
```

{{% alert title="Warning" color="warning" %}}
The above example uses secrets as plain strings. It is recommended to use a [secret store for the secrets]({{< ref component-secrets.md >}}). This component supports storing the `token` parameter and any other sensitive parameter and data as Kubernetes Secrets.
{{% /alert %}}


## Spec metadata fields

| Field              | Required | Details | Example |
|--------------------|:--------:|---------|---------|
| host               | Y  | Address of the Pulsar broker. Default is `"localhost:6650"` | `"localhost:6650"` OR `"http://pulsar-pj54qwwdpz4b-pulsar.ap-sg.public.pulsar.com:8080"`|
| enableTLS          | N  | Enable TLS.  Default: `"false"` | `"true"`, `"false"` |
| tenant             | N  | The topic tenant within the instance. Tenants are essential to multi-tenancy in Pulsar, and spread across clusters.  Default: `"public"` | `"public"` |
| consumerID         | N  | Used to set the subscription name or consumer ID.  | Can be set to string value (such as `"channel1"` in the example above) or string format value (such as `"{podName}"`, etc.). [See all of template tags you can use in your component metadata.]({{< ref "component-schema.md#templated-metadata-values" >}})
| namespace          | N  | The administrative unit of the topic, which acts as a grouping mechanism for related topics.  Default: `"default"` | `"default"`
| persistent         | N  | Pulsar supports two kinds of topics: [persistent](https://pulsar.apache.org/docs/en/concepts-architecture-overview#persistent-storage) and [non-persistent](https://pulsar.apache.org/docs/en/concepts-messaging/#non-persistent-topics). With persistent topics, all messages are durably persisted on disks (if the broker is not standalone, messages are durably persisted on multiple disks), whereas data for non-persistent topics is not persisted to storage disks.
| disableBatching | N | disable batching.When batching enabled default batch delay is set to 10 ms and default batch size is 1000 messages,Setting `disableBatching: true` will make the producer to send messages individually. Default: `"false"` | `"true"`, `"false"`|
| receiverQueueSize | N | Sets the size of the consumer receiver queue. Controls how many messages can be accumulated by the consumer before it is explicitly called to read messages by Dapr. Default: `"1000"` | `"1000"` |
| batchingMaxPublishDelay | N | batchingMaxPublishDelay set the time period within which the messages sent will be batched,if batch messages are enabled. If set to a non zero value, messages will be queued until this time interval or  batchingMaxMessages (see below) or  batchingMaxSize (see below). There are two valid formats, one is the fraction with a unit suffix format, and the other is the pure digital format that is processed as milliseconds. Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h". Default: `"10ms"` | `"10ms"`, `"10"`|
| batchingMaxMessages | N | batchingMaxMessages set the maximum number of messages permitted in a batch.If set to a value greater than 1, messages will be queued until this threshold is reached or  batchingMaxSize (see below) has been reached or the batch interval has elapsed. Default: `"1000"` | `"1000"`|
| batchingMaxSize | N | batchingMaxSize sets the maximum number of bytes permitted in a batch. If set to a value greater than 1, messages will be queued until this threshold is reached or batchingMaxMessages (see above) has been reached or the batch interval has elapsed. Default: `"128KB"` | `"131072"`|
| <topic-name>.jsonschema          | N  | Enforces JSON schema validation for the configured topic. |
| <topic-name>.avroschema          | N  | Enforces Avro schema validation for the configured topic. |
| publicKey          | N  | A public key to be used for publisher and consumer encryption. Value can be one of two options: file path for a local PEM cert, or the cert data string value  |
| privateKey          | N  | A private key to be used for consumer encryption. Value can be one of two options: file path for a local PEM cert, or the cert data string value  |
| keys          | N  | A comma delimited string containing names of [Pulsar session keys](https://pulsar.apache.org/docs/3.0.x/security-encryption/#how-it-works-in-pulsar). Used in conjunction with `publicKey` for publisher encryption |
| processMode | N | Enable processing multiple messages at once. Default: `"async"` | `"async"`, `"sync"`|
| subscribeType | N | Pulsar supports four kinds of [subscription types](https://pulsar.apache.org/docs/3.0.x/concepts-messaging/#subscription-types). Default: `"shared"` | `"shared"`, `"exclusive"`, `"failover"`, `"key_shared"`|
| partitionKey | N | Sets the key of the message for routing policy. Default: `""` | |
| `maxConcurrentHandlers` | N  | Defines the maximum number of concurrent message handlers. Default: `100` | `10`

### Authenticate using Token

To authenticate to pulsar using a static [JWT token](https://pulsar.apache.org/docs/en/security-jwt), you can use the following metadata field:

| Field  | Required | Details | Example |
|--------|:--------:|---------|---------|
| token | N | Token used for authentication. | [How to create Pulsar token](https://pulsar.apache.org/docs/en/security-jwt/#generate-tokens)|

```yaml
apiVersion: dapr.io/v1alpha1
kind: Component
metadata:
  name: messagebus
spec:
  type: pubsub.pulsar
  version: v1
  metadata:
  - name: host
    value: "pulsar.example.com:6650"
  - name: token
    secretKeyRef:
      name: pulsar
      key:  token
```

### Authenticate using OIDC

Since `v3.0`, [Pulsar supports OIDC authentication](https://pulsar.apache.org/docs/3.0.x/security-openid-connect/).
To enable OIDC authentication, you need to provide the following OAuth2 parameters to the component spec.
OAuth2 authentication cannot be used in combination with token authentication.
It is recommended that you use a secret reference for the client secret.
The pulsar OAuth2 authenticator is not specifically complaint with OIDC so it is your responsibility to ensure fields are compliant. For example, the issuer URL must use the `https` protocol, the requested scopes include `openid`, etc.
If the `oauth2TokenCAPEM` field is omitted then the system's certificate pool is used for connecting to the OAuth2 issuer if using `https`.

| Field  | Required | Details | Example |
|--------|:--------:|---------|---------|
| oauth2TokenURL | N | URL to request the OIDC client_credentials token from. Must not be empty. | "https://oauth.example.com/o/oauth2/token"` |
| oauth2TokenCAPEM | N | CA PEM certificate bundle to connect to the OAuth2 issuer. If not defined, the system's certificate pool will be used. | `"---BEGIN CERTIFICATE---\n...\n---END CERTIFICATE---"` |
| oauth2ClientID | N | OIDC client ID. Must not be empty. | `"my-client-id"` |
| oauth2ClientSecret | N | OIDC client secret. Must not be empty. | `"my-client-secret"` |
| oauth2Audiences | N | Comma separated list of audiences to request for. Must not be empty. | `"my-audience-1,my-audience-2"` |
| oauth2Scopes | N | Comma separated list of scopes to request. Must not be empty. | `"openid,profile,email"` |


```yaml
apiVersion: dapr.io/v1alpha1
kind: Component
metadata:
  name: messagebus
spec:
  type: pubsub.pulsar
  version: v1
  metadata:
  - name: host
    value: "pulsar.example.com:6650"
  - name: oauth2TokenURL
    value: https://oauth.example.com/o/oauth2/token
  - name: oauth2TokenCAPEM
    value: "---BEGIN CERTIFICATE---\n...\n---END CERTIFICATE---"
  - name: oauth2ClientID
    value: my-client-id
  - name: oauth2ClientSecret
    secretKeyRef:
      name: pulsar-oauth2
      key:  my-client-secret
  - name: oauth2Audiences
    value: "my.pulsar.example.com,another.pulsar.example.com"
  - name: oauth2Scopes
    value: "openid,profile,email"
```

### Enabling message delivery retries

The Pulsar pub/sub component has no built-in support for retry strategies. This means that sidecar sends a message to the service only once and is not retried in case of failures. To make Dapr use more spohisticated retry policies, you can apply a [retry resiliency policy]({{< ref "retries-overview.md" >}}) to the Pulsar pub/sub component. Note that it will be the same Dapr sidecar retrying the redelivery the message to the same app instance and not other instances.

### Delay queue

When invoking the Pulsar pub/sub, it's possible to provide an optional delay queue by using the `metadata` query parameters in the request url.

These optional parameter names are `metadata.deliverAt` or `metadata.deliverAfter`:

- `deliverAt`: Delay message to deliver at a specified time (RFC3339 format); for example, `"2021-09-01T10:00:00Z"`
- `deliverAfter`: Delay message to deliver after a specified amount of time; for example,`"4h5m3s"`

Examples:

```shell
curl -X POST http://localhost:3500/v1.0/publish/myPulsar/myTopic?metadata.deliverAt='2021-09-01T10:00:00Z' \
  -H "Content-Type: application/json" \
  -d '{
        "data": {
          "message": "Hi"
        }
      }'
```

Or

```shell
curl -X POST http://localhost:3500/v1.0/publish/myPulsar/myTopic?metadata.deliverAfter='4h5m3s' \
  -H "Content-Type: application/json" \
  -d '{
        "data": {
          "message": "Hi"
        }
      }'
```

### E2E Encryption

Dapr supports setting public and private key pairs to enable Pulsar's [end-to-end encryption feature](https://pulsar.apache.org/docs/3.0.x/security-encryption/).

#### Enabling publisher encryption from file certs

```yaml
apiVersion: dapr.io/v1alpha1
kind: Component
metadata:
  name: messagebus
spec:
  type: pubsub.pulsar
  version: v1
  metadata:
  - name: host
    value: "localhost:6650"
  - name: publicKey
    value: ./public.key
  - name: keys
    value: myapp.key
```

#### Enabling consumer encryption from file certs

```yaml
apiVersion: dapr.io/v1alpha1
kind: Component
metadata:
  name: messagebus
spec:
  type: pubsub.pulsar
  version: v1
  metadata:
  - name: host
    value: "localhost:6650"
  - name: publicKey
    value: ./public.key
  - name: privateKey
    value: ./private.key
```

#### Enabling publisher encryption from value

> Note: It is recommended to [reference the public key from a secret]({{< ref component-secrets.md >}}).

```yaml
apiVersion: dapr.io/v1alpha1
kind: Component
metadata:
  name: messagebus
spec:
  type: pubsub.pulsar
  version: v1
  metadata:
  - name: host
    value: "localhost:6650"
  - name: publicKey
    value:  "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1KDAM4L8RtJ+nLaXBrBh\nzVpvTemsKVZoAct8A+ShepOHT9lgHOCGLFGWNla6K6j+b3AV/P/fAAhwj82vwTDd\nruXSflvSdmYeFAw3Ypphc1A5oM53wSRWhg63potBNWqdDzj8ApYgqjpmjYSQdL5/\na3golb36GYFrY0MLFTv7wZ87pmMIPsOgGIcPbCHker2fRZ34WXYLb1hkeUpwx4eK\njpwcg35gccvR6o/UhbKAuc60V1J9Wof2sNgtlRaQej45wnpjWYzZrIyk5qUbn0Qi\nCdpIrXvYtANq0Id6gP8zJvUEdPIgNuYxEmVCl9jI+8eGI6peD0qIt8U80hf9axhJ\n3QIDAQAB\n-----END PUBLIC KEY-----\n"
  - name: keys
    value: myapp.key
```

#### Enabling consumer encryption from value

> Note: It is recommended to [reference the public and private keys from a secret]({{< ref component-secrets.md >}}).

```yaml
apiVersion: dapr.io/v1alpha1
kind: Component
metadata:
  name: messagebus
spec:
  type: pubsub.pulsar
  version: v1
  metadata:
  - name: host
    value: "localhost:6650"
  - name: publicKey
    value: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1KDAM4L8RtJ+nLaXBrBh\nzVpvTemsKVZoAct8A+ShepOHT9lgHOCGLFGWNla6K6j+b3AV/P/fAAhwj82vwTDd\nruXSflvSdmYeFAw3Ypphc1A5oM53wSRWhg63potBNWqdDzj8ApYgqjpmjYSQdL5/\na3golb36GYFrY0MLFTv7wZ87pmMIPsOgGIcPbCHker2fRZ34WXYLb1hkeUpwx4eK\njpwcg35gccvR6o/UhbKAuc60V1J9Wof2sNgtlRaQej45wnpjWYzZrIyk5qUbn0Qi\nCdpIrXvYtANq0Id6gP8zJvUEdPIgNuYxEmVCl9jI+8eGI6peD0qIt8U80hf9axhJ\n3QIDAQAB\n-----END PUBLIC KEY-----\n"
  - name: privateKey
    value: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1KDAM4L8RtJ+nLaXBrBhzVpvTemsKVZoAct8A+ShepOHT9lg\nHOCGLFGWNla6K6j+b3AV/P/fAAhwj82vwTDdruXSflvSdmYeFAw3Ypphc1A5oM53\nwSRWhg63potBNWqdDzj8ApYgqjpmjYSQdL5/a3golb36GYFrY0MLFTv7wZ87pmMI\nPsOgGIcPbCHker2fRZ34WXYLb1hkeUpwx4eKjpwcg35gccvR6o/UhbKAuc60V1J9\nWof2sNgtlRaQej45wnpjWYzZrIyk5qUbn0QiCdpIrXvYtANq0Id6gP8zJvUEdPIg\nNuYxEmVCl9jI+8eGI6peD0qIt8U80hf9axhJ3QIDAQABAoIBAQCKuHnM4ac/eXM7\nQPDVX1vfgyHc3hgBPCtNCHnXfGFRvFBqavKGxIElBvGOcBS0CWQ+Rg1Ca5kMx3TQ\njSweSYhH5A7pe3Sa5FK5V6MGxJvRhMSkQi/lJZUBjzaIBJA9jln7pXzdHx8ekE16\nBMPONr6g2dr4nuI9o67xKrtfViwRDGaG6eh7jIMlEqMMc6WqyhvI67rlVDSTHFKX\njlMcozJ3IT8BtTzKg2Tpy7ReVuJEpehum8yn1ZVdAnotBDJxI07DC1cbOP4M2fHM\ngfgPYWmchauZuTeTFu4hrlY5jg0/WLs6by8r/81+vX3QTNvejX9UdTHMSIfQdX82\nAfkCKUVhAoGBAOvGv+YXeTlPRcYC642x5iOyLQm+BiSX4jKtnyJiTU2s/qvvKkIu\nxAOk3OtniT9NaUAHEZE9tI71dDN6IgTLQlAcPCzkVh6Sc5eG0MObqOO7WOMCWBkI\nlaAKKBbd6cGDJkwGCJKnx0pxC9f8R4dw3fmXWgWAr8ENiekMuvjSfjZ5AoGBAObd\ns2L5uiUPTtpyh8WZ7rEvrun3djBhzi+d7rgxEGdditeiLQGKyZbDPMSMBuus/5wH\nwfi0xUq50RtYDbzQQdC3T/C20oHmZbjWK5mDaLRVzWS89YG/NT2Q8eZLBstKqxkx\ngoT77zoUDfRy+CWs1xvXzgxagD5Yg8/OrCuXOqWFAoGAPIw3r6ELknoXEvihASxU\nS4pwInZYIYGXpygLG8teyrnIVOMAWSqlT8JAsXtPNaBtjPHDwyazfZrvEmEk51JD\nX0tA8M5ah1NYt+r5JaKNxp3P/8wUT6lyszyoeubWJsnFRfSusuq/NRC+1+KDg/aq\nKnSBu7QGbm9JoT2RrmBv5RECgYBRn8Lj1I1muvHTNDkiuRj2VniOSirkUkA2/6y+\nPMKi+SS0tqcY63v4rNCYYTW1L7Yz8V44U5mJoQb4lvpMbolGhPljjxAAU3hVkItb\nvGVRlSCIZHKczADD4rJUDOS7DYxO3P1bjUN4kkyYx+lKUMDBHFzCa2D6Kgt4dobS\n5qYajQKBgQC7u7MFPkkEMqNqNGu5erytQkBq1v1Ipmf9rCi3iIj4XJLopxMgw0fx\n6jwcwNInl72KzoUBLnGQ9PKGVeBcgEgdI+a+tq+1TJo6Ta+hZSx+4AYiKY18eRKG\neNuER9NOcSVJ7Eqkcw4viCGyYDm2vgNV9HJ0VlAo3RDh8x5spEN+mg==\n-----END RSA PRIVATE KEY-----\n"
```

### Partition Key

When invoking the Pulsar pub/sub, it's possible to provide an optional partition key by using the `metadata` query parameter in the request url.

The parameter name is `partitionKey`.

Example:

```shell
curl -X POST http://localhost:3500/v1.0/publish/myPlusar/myTopic?metadata.partitionKey=key1 \
  -H "Content-Type: application/json" \
  -d '{
        "data": {
          "message": "Hi"
        }
      }'
```

### Message headers

All other metadata key/value pairs (that are not `partitionKey`) are set as headers in the Pulsar message. For example, set a `correlationId` for the message:

```shell
curl -X POST http://localhost:3500/v1.0/publish/myPlusar/myTopic?metadata.correlationId=myCorrelationID&metadata.partitionKey=key1 \
  -H "Content-Type: application/json" \
  -d '{
        "data": {
          "message": "Hi"
        }
      }'
```

## Order guarantee

To ensure that messages arrive in order for each consumer subscribed to a specific key, three conditions must be met.

1. `subscribeType` should be set to `key_shared`.
2. `partitionKey` must be set.
3. `processMode` should be set to `sync`.

## Create a Pulsar instance

{{< tabs "Self-Hosted" "Kubernetes">}}

{{% codetab %}}

```
docker run -it \
  -p 6650:6650 \
  -p 8080:8080 \
  --mount source=pulsardata,target=/pulsar/data \
  --mount source=pulsarconf,target=/pulsar/conf \
  apachepulsar/pulsar:2.5.1 \
  bin/pulsar standalone

```

{{% /codetab %}}

{{% codetab %}}
Refer to the following [Helm chart](https://pulsar.apache.org/docs/helm-overview) Documentation.
{{% /codetab %}}

{{< /tabs >}}

## Related links

- [Basic schema for a Dapr component]({{< ref component-schema >}})
- Read [this guide]({{< ref "howto-publish-subscribe.md#step-2-publish-a-topic" >}}) for instructions on configuring pub/sub components
- [Pub/Sub building block]({{< ref pubsub >}})

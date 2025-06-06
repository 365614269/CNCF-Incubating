---
type: docs
title: "Publishing & subscribing messages without CloudEvents"
linkTitle: "Messages without CloudEvents"
weight: 2200
description: "Learn when you might not use CloudEvents and how to disable them."
---

When adding Dapr to your application, some services may still need to communicate via pub/sub messages not encapsulated in CloudEvents, due to either compatibility reasons or some apps not using Dapr. These are referred to as "raw" pub/sub messages. Dapr enables apps to [publish and subscribe to raw events]({{< ref "pubsub-cloudevents.md#publishing-raw-messages" >}}) not wrapped in a CloudEvent for compatibility and to send data that is not JSON serializable.

## Publishing raw messages

Dapr apps are able to publish raw events to pub/sub topics without CloudEvent encapsulation, for compatibility with non-Dapr apps.

<img src="/images/pubsub_publish_raw.png" alt="Diagram showing how to publish with Dapr when subscriber does not use Dapr or CloudEvent" width=1000>

{{% alert title="Warning" color="warning" %}}
Not using CloudEvents disables support for tracing, event deduplication per messageId, content-type metadata, and any other features built using the CloudEvent schema.
{{% /alert %}}

To disable CloudEvent wrapping, set the `rawPayload` metadata to `true` as part of the publishing request. This allows subscribers to receive these messages without having to parse the CloudEvent schema.

{{< tabs curl ".NET" "Python" "PHP">}}

{{% codetab %}}
```bash
curl -X "POST" http://localhost:3500/v1.0/publish/pubsub/TOPIC_A?metadata.rawPayload=true -H "Content-Type: application/json" -d '{"order-number": "345"}'
```
{{% /codetab %}}

{{% codetab %}}

```csharp
using Dapr.Client;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers().AddDapr();

var app = builder.Build();

app.MapPost("/publish", async (DaprClient daprClient) =>
{
    var message = new Message(
        Guid.NewGuid().ToString(),
        $"Hello at {DateTime.UtcNow}",
        DateTime.UtcNow
    );

    await daprClient.PublishEventAsync(
        "pubsub",           // pubsub name
        "messages",         // topic name
        message,           // message data
        new Dictionary<string, string> 
        { 
            { "rawPayload", "true" },
            { "content-type", "application/json" }
        }
    );
    
    return Results.Ok(message);
});

app.Run();
```

{{% /codetab %}}

{{% codetab %}}
```python
from dapr.clients import DaprClient

with DaprClient() as d:
    req_data = {
        'order-number': '345'
    }
    # Create a typed message with content type and body
    resp = d.publish_event(
        pubsub_name='pubsub',
        topic_name='TOPIC_A',
        data=json.dumps(req_data),
        publish_metadata={'rawPayload': 'true'}
    )
    # Print the request
    print(req_data, flush=True)
```
{{% /codetab %}}

{{% codetab %}}

```php
<?php

require_once __DIR__.'/vendor/autoload.php';

$app = \Dapr\App::create();
$app->run(function(\DI\FactoryInterface $factory) {
    $publisher = $factory->make(\Dapr\PubSub\Publish::class, ['pubsub' => 'pubsub']);
    $publisher->topic('TOPIC_A')->publish('data', ['rawPayload' => 'true']);
});
```

{{% /codetab %}}

{{< /tabs >}}

## Subscribing to raw messages

Dapr apps can subscribe to raw messages from pub/sub topics, even if they weren’t published as CloudEvents. However, the subscribing Dapr process still wraps these raw messages in a CloudEvent before delivering them to the subscribing application.

<img src="/images/pubsub_subscribe_raw.png" alt="Diagram showing how to subscribe with Dapr when publisher does not use Dapr or CloudEvent" width=1000>

### Programmatically subscribe to raw events

When subscribing programmatically, add the additional metadata entry for `rawPayload` to allow the subscriber to receive a message that is not wrapped by a CloudEvent. For .NET, this metadata entry is called `isRawPayload`. 

When using raw payloads the message is always base64 encoded with content type `application/octet-stream`.

{{< tabs ".NET" "Python" "PHP" >}}

{{% codetab %}}

```csharp
using System.Text.Json;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/dapr/subscribe", () =>
{
    var subscriptions = new[]
    {
        new
        {
            pubsubname = "pubsub",
            topic = "messages",
            route = "/messages",
            metadata = new Dictionary<string, string>
            {
                { "isRawPayload", "true" },
                { "content-type", "application/json" }
            }
        }
    };
    return Results.Ok(subscriptions);
});

app.MapPost("/messages", async (HttpContext context) =>
{
    using var reader = new StreamReader(context.Request.Body);
    var json = await reader.ReadToEndAsync();

    Console.WriteLine($"Raw message received: {json}");

    return Results.Ok();
});

app.Run();
```

{{% /codetab %}}

{{% codetab %}}

```python
import flask
from flask import request, jsonify
from flask_cors import CORS
import json
import sys

app = flask.Flask(__name__)
CORS(app)

@app.route('/dapr/subscribe', methods=['GET'])
def subscribe():
    subscriptions = [{'pubsubname': 'pubsub',
                      'topic': 'deathStarStatus',
                      'route': 'dsstatus',
                      'metadata': {
                          'rawPayload': 'true',
                      } }]
    return jsonify(subscriptions)

@app.route('/dsstatus', methods=['POST'])
def ds_subscriber():
    print(request.json, flush=True)
    return json.dumps({'success':True}), 200, {'ContentType':'application/json'}

app.run()
```

{{% /codetab %}}
{{% codetab %}}

```php
<?php

require_once __DIR__.'/vendor/autoload.php';

$app = \Dapr\App::create(configure: fn(\DI\ContainerBuilder $builder) => $builder->addDefinitions(['dapr.subscriptions' => [
    new \Dapr\PubSub\Subscription(pubsubname: 'pubsub', topic: 'deathStarStatus', route: '/dsstatus', metadata: [ 'rawPayload' => 'true'] ),
]]));

$app->post('/dsstatus', function(
    #[\Dapr\Attributes\FromBody]
    \Dapr\PubSub\CloudEvent $cloudEvent,
    \Psr\Log\LoggerInterface $logger
    ) {
        $logger->alert('Received event: {event}', ['event' => $cloudEvent]);
        return ['status' => 'SUCCESS'];
    }
);

$app->start();
```
{{% /codetab %}}

{{< /tabs >}}

## Declaratively subscribe to raw events

Similarly, you can subscribe to raw events declaratively by adding the `rawPayload` metadata entry to your subscription specification.

```yaml
apiVersion: dapr.io/v2alpha1
kind: Subscription
metadata:
  name: myevent-subscription
spec:
  topic: deathStarStatus
  routes: 
    default: /dsstatus
  pubsubname: pubsub
  metadata:
    isRawPayload: "true"
scopes:
- app1
- app2
```

## Next steps

- Learn more about [publishing and subscribing messages]({{< ref pubsub-overview.md >}})
- List of [pub/sub components]({{< ref supported-pubsub >}})
- Read the [API reference]({{< ref pubsub_api.md >}})
- Read the .NET sample on how to [consume Kafka messages without CloudEvents](https://github.com/dapr/samples/pubsub-raw-payload)

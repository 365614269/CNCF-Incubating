# Connecting to a Specific Server

The NATS client libraries can take a full URL, `nats://demo.nats.io:4222`, to specify a specific server host and port to connect to.

Libraries are removing the requirement for an explicit protocol and may allow `demo.nats.io:4222` or just `demo.nats.io`. In the later example the default port 4222 will be used. Check with your specific client library's documentation to see what URL formats are supported.

For example, to connect to the demo server with a URL you can use:

{% tabs %}
{% tab title="Go" %}
```java
// If connecting to the default port, the URL can be simplified
// to just the hostname/IP.
// That is, the connect below is equivalent to:
// nats.Connect("nats://demo.nats.io:4222")
nc, err := nats.Connect("demo.nats.io")
if err != nil {
    log.Fatal(err)
}
defer nc.Close()

// Do something with the connection nc = Nats.connect("nats://demo.nats.io:4222");
```
{% endtab %}

{% tab title="Java" %}
```text
// Connection is AutoCloseable
try (Connection nc = Nats.connect("nats://demo.nats.io:4222")) {
    // Do something with the connection
}
```
{% endtab %}

{% tab title="JavaScript" %}
```javascript
const nc = await connect({ servers: "demo.nats.io" });
// Do something with the connection
doSomething();
await nc.close();
```
{% endtab %}

{% tab title="Python" %}
```python
nc = NATS()
await nc.connect(servers=["nats://demo.nats.io:4222"])

# Do something with the connection

await nc.close()
```
{% endtab %}

{% tab title="C# v1" %}
```csharp
// IConnection is IDisposable
using (IConnection c = new ConnectionFactory().CreateConnection("nats://demo.nats.io:4222"))
{
    // Do something with the connection
}
```
{% endtab %}

{% tab title="C# v2" %}
```csharp
// NATS server URL is part of the connection options
var opts = new NatsOpts { Url = "nats://demo.nats.io:4222" };

// NatsConnection is IAsyncDisposable
await using var nats = new NatsConnection(opts);

// Do something with the connection
```
{% endtab %}

{% tab title="Ruby" %}
```ruby
require 'nats/client'

NATS.start(servers: ["nats://demo.nats.io:4222"]) do |nc|
   # Do something with the connection

   # Close the connection
   nc.close
end
```
{% endtab %}

{% tab title="C" %}
```c
natsConnection      *conn = NULL;
natsStatus          s;

// If connecting to the default port, the URL can be simplified
// to just the hostname/IP.
// That is, the connect below is equivalent to:
// natsConnection_ConnectTo(&conn, "nats://demo.nats.io:4222");
s = natsConnection_ConnectTo(&conn, "demo.nats.io");
if (s != NATS_OK)
  // handle error

// Destroy connection, no-op if conn is NULL.
natsConnection_Destroy(conn);
```
{% endtab %}

{% endtabs %}


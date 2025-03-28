---
title: Resources
weight: 70
cSpell:ignore: myhost pcarter uuidgen
---

{{% docs/languages/resources-intro %}}

## Setup

Follow the instructions in the [Getting Started][], so that you have a running
.NET app exporting data to the console.

## Adding resources with environment variables

You can use the `OTEL_RESOURCE_ATTRIBUTES` environment variable to inject
resources into your application. The .NET SDK will automatically detect these
resources.

The following example adds [Service][], [Host][] and [OS][] resource attributes
via environment variables, running unix programs like `uname` to generate the
resource data.

```console
$ env OTEL_RESOURCE_ATTRIBUTES="service.name=resource-tutorial-dotnet,service.namespace=tutorial,service.version=1.0,service.instance.id=`uuidgen`,host.name=`HOSTNAME`,host.type=`uname -m`,os.name=`uname -s`,os.version=`uname -r`" dotnet run

Activity.TraceId:          d1cbb7787440cc95b325835cb2ff8018
Activity.SpanId:           2ca007300fcb3068
Activity.TraceFlags:           Recorded
Activity.ActivitySourceName: tutorial-dotnet
Activity.DisplayName: SayHello
Activity.Kind:        Internal
Activity.StartTime:   2022-10-02T13:31:12.0175090Z
Activity.Duration:    00:00:00.0003920
Activity.Tags:
    foo: 1
    bar: Hello, World!
    baz: [1,2,3]
Resource associated with Activity:
    service.name: resource-tutorial-dotnet
    service.namespace: tutorial
    service.version: 1.0
    service.instance.id: 93B14BAD-813D-48EE-9FB1-2ADFD07C5E78
    host.name: myhost
    host.type: arm64
    os.name: Darwin
    os.version: 21.6.0
```

## Adding resources in code

You can also add custom resources in code by attaching them to a
`ResourceBuilder`.

The following example builds on the [getting started] sample and adds two custom
resources, `environment.name` and `team.name` in code:

```csharp
using System.Diagnostics;
using System.Collections.Generic;

using OpenTelemetry;
using OpenTelemetry.Trace;
using OpenTelemetry.Resources;

var serviceName = "resource-tutorial-dotnet";
var serviceVersion = "1.0";

var resourceBuilder =
    ResourceBuilder
        .CreateDefault()
        .AddService(serviceName: serviceName, serviceVersion: serviceVersion)
        .AddAttributes(new Dictionary<string, object>
        {
            ["environment.name"] = "production",
            ["team.name"] = "backend"
        });

var sourceName = "tutorial-dotnet";

using var tracerProvider = Sdk.CreateTracerProviderBuilder()
    .AddSource(sourceName)
    .SetResourceBuilder(resourceBuilder)
    .AddConsoleExporter()
    .Build();

var MyActivitySource = new ActivitySource(sourceName);

using var activity = MyActivitySource.StartActivity("SayHello");
activity?.SetTag("foo", 1);
activity?.SetTag("bar", "Hello, World!");
activity?.SetTag("baz", new int[] { 1, 2, 3 });
```

In this example, the `service.name` and `service.version` values are set in code
as well. Additionally, `service.instance.id` gets a default value.

If you run the same command as in
[Adding resources with environment variables](#adding-resources-with-environment-variables),
but this time without `service.name` `service.version`, and
`service.instance.id`, you'll see the `environment.name` and `team.name`
resources in the resource list:

```console
$ env OTEL_RESOURCE_ATTRIBUTES="service.namespace=tutorial,host.name=`HOSTNAME`,host.type=`uname -m`,os.name=`uname -s`,os.version=`uname -r`" dotnet run

Activity.TraceId:          d1cbb7787440cc95b325835cb2ff8018
Activity.SpanId:           2ca007300fcb3068
Activity.TraceFlags:           Recorded
Activity.ActivitySourceName: tutorial-dotnet
Activity.DisplayName: SayHello
Activity.Kind:        Internal
Activity.StartTime:   2022-10-02T13:31:12.0175090Z
Activity.Duration:    00:00:00.0003920
Activity.Tags:
    foo: 1
    bar: Hello, World!
    baz: [1,2,3]
Resource associated with Activity:
    environment.name: production
    team.name: backend
    service.name: resource-tutorial-dotnet
    service.namespace: tutorial
    service.version: 1.0
    service.instance.id: 28976A1C-BF02-43CA-BAE0-6E0564431462
    host.name: pcarter
    host.type: arm64
    os.name: Darwin
    os.version: 21.6.0
```

**Note**: If you set resource attributes with both environment variables and
code, the values in code take precedence.

## Next steps

There are more resource detectors you can add to your configuration, for example
to get details about your [Cloud] environment or [Deployment][].

[getting started]: /docs/languages/dotnet/getting-started/
[host]: /docs/specs/semconv/resource/host/
[cloud]: /docs/specs/semconv/resource/cloud/
[deployment]: /docs/specs/semconv/resource/deployment-environment/
[service]: /docs/specs/semconv/resource/#service
[os]: /docs/specs/semconv/resource/os/

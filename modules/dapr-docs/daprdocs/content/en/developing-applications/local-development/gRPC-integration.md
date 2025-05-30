---
type: docs
title: "How to: Use the gRPC interface in your Dapr application"
linkTitle: "gRPC interface"
weight: 400
description: "Use the Dapr gRPC API in your application"
---

Dapr implements both an HTTP and a gRPC API for local calls. [gRPC](https://grpc.io/) is useful for low-latency, high performance scenarios and has language integration using the proto clients.

[Find a list of auto-generated clients in the Dapr SDK documentation]({{< ref sdks >}}).

The Dapr runtime implements a [proto service](https://github.com/dapr/dapr/blob/master/dapr/proto/runtime/v1/dapr.proto) that apps can communicate with via gRPC.

In addition to calling Dapr via gRPC, Dapr supports service-to-service calls with gRPC by acting as a proxy. [Learn more in the gRPC service invocation how-to guide]({{< ref howto-invoke-services-grpc.md >}}).

This guide demonstrates configuring and invoking Dapr with gRPC using a Go SDK application.

## Configure Dapr to communicate with an app via gRPC

{{< tabs "Self-hosted" "Kubernetes">}}
<!--selfhosted-->
{{% codetab %}}

When running in self-hosted mode, use the `--app-protocol` flag to tell Dapr to use gRPC to talk to the app.

```bash
dapr run --app-protocol grpc --app-port 5005 node app.js
```

This tells Dapr to communicate with your app via gRPC over port `5005`.

{{% /codetab %}}

<!--k8s-->
{{% codetab %}}

On Kubernetes, set the following annotations in your deployment YAML:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  namespace: default
  labels:
    app: myapp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
      annotations:
        dapr.io/enabled: "true"
        dapr.io/app-id: "myapp"
        dapr.io/app-protocol: "grpc"
        dapr.io/app-port: "5005"
...
```

{{% /codetab %}}

{{< /tabs >}}

## Invoke Dapr with gRPC

The following steps show how to create a Dapr client and call the `SaveStateData` operation on it.

1. Import the package:

    ```go
    package main
    
    import (
    	"context"
    	"log"
    	"os"
    
    	dapr "github.com/dapr/go-sdk/client"
    )
    ```

1. Create the client:

    ```go
    // just for this demo
    ctx := context.Background()
    data := []byte("ping")
    
    // create the client
    client, err := dapr.NewClient()
    if err != nil {
      log.Panic(err)
    }
    defer client.Close()
    ```
    
    3. Invoke the `SaveState` method:
    
    ```go
    // save state with the key key1
    err = client.SaveState(ctx, "statestore", "key1", data)
    if err != nil {
      log.Panic(err)
    }
    log.Println("data saved")
    ```

Now you can explore all the different methods on the Dapr client.

## Create a gRPC app with Dapr

The following steps will show how to create an app that exposes a server for with which Dapr can communicate.

1. Import the package:

    ```go
    package main
    
    import (
    	"context"
    	"fmt"
    	"log"
    	"net"
    
    	"github.com/golang/protobuf/ptypes/any"
    	"github.com/golang/protobuf/ptypes/empty"
    
    	commonv1pb "github.com/dapr/dapr/pkg/proto/common/v1"
    	pb "github.com/dapr/dapr/pkg/proto/runtime/v1"
    	"google.golang.org/grpc"
    )
    ```

1. Implement the interface:

    ```go
    // server is our user app
    type server struct {
         pb.UnimplementedAppCallbackServer
    }
    
    // EchoMethod is a simple demo method to invoke
    func (s *server) EchoMethod() string {
    	return "pong"
    }
    
    // This method gets invoked when a remote service has called the app through Dapr
    // The payload carries a Method to identify the method, a set of metadata properties and an optional payload
    func (s *server) OnInvoke(ctx context.Context, in *commonv1pb.InvokeRequest) (*commonv1pb.InvokeResponse, error) {
    	var response string
    
    	switch in.Method {
    	case "EchoMethod":
    		response = s.EchoMethod()
    	}
    
    	return &commonv1pb.InvokeResponse{
    		ContentType: "text/plain; charset=UTF-8",
    		Data:        &any.Any{Value: []byte(response)},
    	}, nil
    }
    
    // Dapr will call this method to get the list of topics the app wants to subscribe to. In this example, we are telling Dapr
    // To subscribe to a topic named TopicA
    func (s *server) ListTopicSubscriptions(ctx context.Context, in *empty.Empty) (*pb.ListTopicSubscriptionsResponse, error) {
    	return &pb.ListTopicSubscriptionsResponse{
    		Subscriptions: []*pb.TopicSubscription{
    			{Topic: "TopicA"},
    		},
    	}, nil
    }
    
    // Dapr will call this method to get the list of bindings the app will get invoked by. In this example, we are telling Dapr
    // To invoke our app with a binding named storage
    func (s *server) ListInputBindings(ctx context.Context, in *empty.Empty) (*pb.ListInputBindingsResponse, error) {
    	return &pb.ListInputBindingsResponse{
    		Bindings: []string{"storage"},
    	}, nil
    }
    
    // This method gets invoked every time a new event is fired from a registered binding. The message carries the binding name, a payload and optional metadata
    func (s *server) OnBindingEvent(ctx context.Context, in *pb.BindingEventRequest) (*pb.BindingEventResponse, error) {
    	fmt.Println("Invoked from binding")
    	return &pb.BindingEventResponse{}, nil
    }
    
    // This method is fired whenever a message has been published to a topic that has been subscribed. Dapr sends published messages in a CloudEvents 0.3 envelope.
    func (s *server) OnTopicEvent(ctx context.Context, in *pb.TopicEventRequest) (*pb.TopicEventResponse, error) {
    	fmt.Println("Topic message arrived")
            return &pb.TopicEventResponse{}, nil
    }
    
    ```

1. Create the server:

    ```go
    func main() {
    	// create listener
    	lis, err := net.Listen("tcp", ":50001")
    	if err != nil {
    		log.Fatalf("failed to listen: %v", err)
    	}
    
    	// create grpc server
    	s := grpc.NewServer()
    	pb.RegisterAppCallbackServer(s, &server{})
    
    	fmt.Println("Client starting...")
    
    	// and start...
    	if err := s.Serve(lis); err != nil {
    		log.Fatalf("failed to serve: %v", err)
    	}
    }
    ```

   This creates a gRPC server for your app on port 50001.

## Run the application

{{< tabs "Self-hosted" "Kubernetes">}}
<!--selfhosted-->
{{% codetab %}}

To run locally, use the Dapr CLI:

```bash
dapr run --app-id goapp --app-port 50001 --app-protocol grpc go run main.go
```

{{% /codetab %}}

<!--k8s-->
{{% codetab %}}

On Kubernetes, set the required `dapr.io/app-protocol: "grpc"` and `dapr.io/app-port: "50001` annotations in your pod spec template, as mentioned above.

{{% /codetab %}}

{{< /tabs >}}
    

## Other languages

You can use Dapr with any language supported by Protobuf, and not just with the currently available generated SDKs.

Using the [protoc](https://developers.google.com/protocol-buffers/docs/downloads) tool, you can generate the Dapr clients for other languages like Ruby, C++, Rust, and others.

 ## Related Topics
- [Service invocation building block]({{< ref service-invocation >}})
- [Service invocation API specification]({{< ref service_invocation_api.md >}})

# Building Services

Recently we have agreed upon an [initial specification](https://github.com/nats-io/nats-architecture-and-design/blob/main/adr/ADR-32.md) for a services protocol so that we can add first-class services support to NATS clients and support this in our tooling. This services protocol is an agreement between clients and tooling and doesn't require any special functionality from the NATS server or JetStream.

To check if the NATS client in your favorite language supports the new services API, make sure you check the docs and GitHub repository for that client. The services API is relatively new and not all clients may support it yet.

To see the services API in action in different languages, take a look at the [NATS By Example](https://natsbyexample.com/examples/services/intro/go) samples.

## Concepts

There are a few high level concepts in the services API worth understanding before you start developing your own services.

### Service

The service is the highest level abstraction and refers to a group of logically related functionality. Services are required to have names and versions that conform to the [semver](https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string) rules. Services are discoverable within a NATS system.

### Endpoint

A service endpoint is the entity with which clients interact. You can think of an endpoint as a single operation within a service. All services must have at least 1 endpoint.

### Group

A group is a collection of endpoints. These are optional and can provide a logical association between endpoints as well as an optional common subject prefix for all endpoints.

## Service Operations

The services API supports 3 operations for discoverability and observability. While the NATS client will take care of responding on these subjects, it is still the developer's responsibility to respond to requests made the service's actual endpoints.

* `PING` - Requests made on the `$SRV.PING.>` subject gather replies from running services. This facilitates service listing by tooling.
* `STATS` - Requests made on the `$SRV.STATS.>` subject query statistics from services. Available stats include total requests, total errors, and total processing time.
* `INFO` - Requests made on the `$SRV.INFO.>` subject obtain the service definition and metadata, including groups, endpoints, etc.

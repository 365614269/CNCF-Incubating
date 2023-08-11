+++
title="Specifying an Image Extension in the Builder"
weight=405
+++

<!-- test:suite=dockerfiles;weight=5 -->

### Specifying an Image Extension in the Builder

You're pretty sharp, and you know what your buildpack users will need.
That's why you're going to add something similar to the following lines directly to `builder.toml`:

```
[[order-extensions]]
[[order-extensions.group]]
id = "foo"
version = "0.0.1"

[[extensions]]
id = "foo"
version = "0.0.1"
uri = "/local/path/to/extension/foo" # can be relative or absolute
```



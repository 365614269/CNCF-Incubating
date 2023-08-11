+++
title="Why Dockerfiles"
weight=402
aliases = [
  "/docs/extension-author-guide/create-extension/why-dockerfiles/",
  ]
+++

<!-- test:suite=dockerfiles;weight=2 -->

Let's see a build that requires base image extension in order to succeed.

### Examine `hello-extensions` buildpack

#### detect

<!-- test:exec -->
```bash
cat $PWD/samples/buildpacks/hello-extensions/bin/detect
```

The buildpack always detects (because its exit code is `0`) but doesn't require any dependencies (as the output build plan is empty).

#### build

<!-- test:exec -->
```bash
cat $PWD/samples/buildpacks/hello-extensions/bin/build
```

The buildpack tries to use `tree` at build-time, and defines a launch process called `curl` that runs `curl --version` at runtime.

### Create a builder with extensions and publish it

For now, it is necessary for the builder image to be pushed to an OCI registry for builds with image extensions to succeed.

For demo purposes, we will launch a local unauthenticated registry:

<!-- test:exec -->
```bash
docker run -d --rm -p 5000:5000 registry:2
```

You can push the builder to any registry of your choice - just ensure that `docker login` succeeds and replace `localhost:5000` in the following examples with your registry namespace -
e.g., `index.docker.io/<username>`.

Create the builder:

<!-- test:exec -->
```bash
pack builder create localhost:5000/extensions-builder \
  --config $PWD/samples/builders/alpine/builder.toml \
  --publish
```

### Build the application image

Run `pack build` (note that the "source" directory is effectively ignored in our example):

```
pack build hello-extensions \
  --builder localhost:5000/extensions-builder \
  --env BP_EXT_DEMO=1 \
  --network host \
  --path $PWD/samples/apps/java-maven \
  --pull-policy always \
  --verbose
```

Note that `--network host` is necessary when publishing to a local registry.

You should see:

```
[detector] ======== Results ========
[detector] pass: samples/tree@0.0.1
[detector] pass: samples/hello-extensions@0.0.1
[detector] Resolving plan... (try #1)
[detector] skip: samples/tree@0.0.1 provides unused tree
[detector] 1 of 2 buildpacks participating
[detector] samples/hello-extensions 0.0.1
...
[extender] Running build command
[extender] ---> Hello Extensions Buildpack
[extender] /cnb/buildpacks/samples_hello-extensions/0.0.1/bin/build: line 6: tree: command not found
[extender] ERROR: failed to build: exit status 127
```

What happened: our builder doesn't have `tree` installed, so the `hello-extensions` buildpack failed to build (as it
tries to run `tree --version` in its `./bin/build` script).

Even though there is a `samples/tree` extension that passed detection (`pass: samples/tree@0.0.1`), because
the `hello-extensions` buildpack didn't require `tree` in the build plan, the extension was omitted from the detected
group (`skip: samples/tree@0.0.1 provides unused tree`).

Let's take a look at how the `samples/tree` extension installs `tree` on the builder image...

<!--+ if false+-->
---

<a href="/docs/extension-guide/create-extension/building-blocks-extension" class="button bg-pink">Next Step</a>
<!--+ end +-->

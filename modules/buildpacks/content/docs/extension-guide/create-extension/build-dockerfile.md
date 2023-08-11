+++
title="Generating a build.Dockerfile"
weight=404
aliases = [
  "/docs/extension-author-guide/create-extension/build-dockerfile/",
  ]
+++

<!-- test:suite=dockerfiles;weight=4 -->

### Examine `vim` extension

#### detect

<!-- test:exec -->
```bash
cat $PWD/samples/extensions/vim/bin/detect
```

The extension always detects (because its exit code is `0`) and provides a dependency called `vim` by writing to the build plan.

#### generate

<!-- test:exec -->
```bash
cat $PWD/samples/extensions/vim/bin/generate
```

The extension generates a `build.Dockerfile` that installs `vim` on the builder image.

### Re-build the application image

<!-- test:exec -->
```
pack build hello-extensions \
  --builder localhost:5000/extensions-builder \
  --env BP_EXT_DEMO=1 \
  --env BP_REQUIRES=vim \
  --network host \
  --path $PWD/samples/apps/java-maven \
  --pull-policy always \
  --verbose
```

Note that `--network host` is necessary when publishing to a local registry.

You should see:

```
[detector] ======== Results ========
[detector] pass: samples/vim@0.0.1
[detector] pass: samples/hello-extensions@0.0.1
[detector] Resolving plan... (try #1)
[detector] samples/vim             0.0.1
[detector] samples/hello-extensions 0.0.1
[detector] Running generate for extension samples/vim@0.0.1
...
[extender] Found build Dockerfile for extension 'samples/vim'
[extender] Applying the Dockerfile at /layers/generated/build/samples_vim/Dockerfile...
...
[extender] Running build command
[extender] ---> Hello Extensions Buildpack
[extender] vim v1.8.0 (c) 1996 - 2018 by Steve Baker, Thomas Moore, Francesc Rocher, Florian Sesser, Kyosuke Tokoro
...
Successfully built image hello-extensions
```

### See the image fail to run

```
docker run --rm hello-extensions
```

You should see:

```
ERROR: failed to launch: path lookup: exec: "curl": executable file not found in $PATH
```

What happened: our builder uses run image `cnbs/sample-stack-run:alpine`, which does not have `curl` installed, so our
  process failed to launch.

Let's take a look at how the `samples/curl` extension fixes the error by switching the run image to another image...

<!--+ if false+-->
---

<a href="/docs/extension-guide/create-extension/run-dockerfile" class="button bg-pink">Next Step</a>
<!--+ end +-->

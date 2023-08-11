+++
title="Build an app"
weight=1
summary="The basics of taking your app from source code to runnable image."
aliases=[
    "/docs/using-pack/building-app/"
]
+++
<!--+- if false+-->
<div class="quote mb-4">
    {{< summary "docs/concepts/operations/build.md" >}}
    <div class="author"><a href="/docs/concepts/operations/build">build</a></div>
</div>
<!--+- end+-->
<!--+- `
# Build an app
`+-->

Building an app using Cloud Native Buildpacks is as easy as `1`, `2`, `3`...

### 1. Select a builder

To [build][build] an app you must first decide which [builder][builder] you're going to use. A builder
includes the [buildpacks][buildpack] that will be used as well as the environment for building your
app.

When using `pack`, you can run `pack builder suggest` for a list of suggested builders.

```
pack builder suggest
```
<!--+- "{{execute}}"+-->

For this guide we're actually going to use a sample builder, `cnbs/sample-builder:jammy`, which is not listed
as a suggested builder for good reason. It's a sample.

### 2. Build your app

Now that you've decided on what builder to use, we can build our app. For this example we'll use our [samples][samples]
repo for simplicity.

1. Check that the samples repo exists and if not - we clone it
```
ls samples || git clone https://github.com/buildpacks/samples
```
<!--+- "{{execute}}"+-->

2. Build the app
```
pack build sample-app --path samples/apps/java-maven --builder cnbs/sample-builder:jammy
```
<!--+- "{{execute}}"+-->

> **TIP:** If you don't want to keep specifying a builder every time you build, you can set it as your default
> builder by running `pack config default-builder <BUILDER>` for example `pack config default-builder cnbs/sample-builder:jammy`
<!--+- "{{execute}}"+-->

### 3. Run it

```
docker run --rm -p 8080:8080 sample-app
```
<!--+- "{{execute}}"+-->

**Congratulations!**

<!--+- if false+-->
The app should now be running and accessible via [localhost:8080](http://localhost:8080).
<!--+end+-->

<!--+ `
Now open your favorite browser and point it to port "8080" of your host and take a minute to enjoy the view.

On Katacoda you can do this by [clicking here](https://[[HOST_SUBDOMAIN]]-8080-[[KATACODA_HOST]].environments.katacoda.com)
` +-->

## What about ARM apps?

Linux ARM image builds are now supported!

<!--+- if false+-->
<a href="/docs/app-developer-guide/build-an-arm-app" class="button bg-blue">Linux ARM build guide</a>
<!--+end+-->

<!--+ `
Check out the [Linux ARM build guide](https://buildpacks.io//docs/app-developer-guide/build-an-arm-app).
` +-->
## What about Windows apps?

Windows image builds are now supported!

<!--+- if false+-->
<a href="/docs/app-developer-guide/build-a-windows-app" class="button bg-blue">Windows build guide</a>
<!--+end+-->
<!--+ `
Check out the [Windows build guide](https://buildpacks.io/docs/app-developer-guide/build-a-windows-app/).
` +-->

[build]: /docs/concepts/operations/build
[builder]: /docs/concepts/components/builder
[buildpack]: /docs/concepts/components/buildpack
[samples]: https://github.com/buildpacks/samples

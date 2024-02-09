# Changelog

## [0.9.0](https://github.com/keptn/lifecycle-toolkit/compare/lifecycle-operator-v0.8.3...lifecycle-operator-v0.9.0) (2024-02-08)


### ⚠ BREAKING CHANGES

* **lifecycle-operator:** Pre/Post evaluations and tasks for an application are now defined in the newly introduced `KeptnAppContext` instead of the `KeptnApp` CRD. `KeptnApps` are now fully managed by the operator and are not intended to be created by the user. The version of a `KeptnApp` will be automatically derived as a function of all workloads that belong to the same application.
* **lifecycle-operator:** move API HUB version to v1beta1 ([#2772](https://github.com/keptn/lifecycle-toolkit/issues/2772))
* **lifecycle-operator:** The environment variable `OTEL_COLLECTOR_URL` is not supported in the lifecycle-operator anymore, and the OTel collector URL is now only set via the `spec.OTelCollectorUrl` property of the `KeptnConfig` CRD. This means that, in order to use Keptn's OpenTelemetry capabilities, the `spec.OtelCollectorUrl` needs to be specified in the `KeptnConfig` resource.
* rename KLT to Keptn ([#2554](https://github.com/keptn/lifecycle-toolkit/issues/2554))
* **lifecycle-operator:** The environment variable giving deno and python runtime access to context information has been renamed from `CONTEXT` to `KEPTN_CONTEXT`

### Features

* add annotation to select container for version extraction ([#2471](https://github.com/keptn/lifecycle-toolkit/issues/2471)) ([d093860](https://github.com/keptn/lifecycle-toolkit/commit/d093860732798b0edb58abedf567558a2c07ad21))
* add configurable service account to KeptnTasks ([#2254](https://github.com/keptn/lifecycle-toolkit/issues/2254)) ([e7db66f](https://github.com/keptn/lifecycle-toolkit/commit/e7db66f91a638759d9d95ef34fa22f59a8a37f9d))
* introduce configurable support of cert-manager.io CA injection ([#2811](https://github.com/keptn/lifecycle-toolkit/issues/2811)) ([d6d83c7](https://github.com/keptn/lifecycle-toolkit/commit/d6d83c7f67a18a4b30aabe774a8fa2c93399f301))
* introduce configurable TTLSecondsAfterFinished for tasks ([#2404](https://github.com/keptn/lifecycle-toolkit/issues/2404)) ([8341dbf](https://github.com/keptn/lifecycle-toolkit/commit/8341dbf256b23d342226b9c44a2057e4fd775854))
* **lifecycle-operator:** add `KEPTN_CONTEXT` to task container env vars ([#2516](https://github.com/keptn/lifecycle-toolkit/issues/2516)) ([a18a833](https://github.com/keptn/lifecycle-toolkit/commit/a18a83306fed5636a971565e12b2e71d315b75b4))
* **lifecycle-operator:** add context metadata and traceParent of current phase to tasks ([#2858](https://github.com/keptn/lifecycle-toolkit/issues/2858)) ([0798406](https://github.com/keptn/lifecycle-toolkit/commit/0798406108b545e8f7debceae5dc1cb28f0a8d11))
* **lifecycle-operator:** add Helm value for DORA metrics port ([#2571](https://github.com/keptn/lifecycle-toolkit/issues/2571)) ([bf472a3](https://github.com/keptn/lifecycle-toolkit/commit/bf472a34efcda14ccb78869aa141a8cd981f4839))
* **lifecycle-operator:** add option to exclude additional namespaces ([#2536](https://github.com/keptn/lifecycle-toolkit/issues/2536)) ([fd42ac7](https://github.com/keptn/lifecycle-toolkit/commit/fd42ac7325927fa6f2f0cfe6875f055fd2cd1be0))
* **lifecycle-operator:** introduce keptnappcontext crd ([#2769](https://github.com/keptn/lifecycle-toolkit/issues/2769)) ([4e7751a](https://github.com/keptn/lifecycle-toolkit/commit/4e7751ae7344d8334db5bd8e6e4463e87eb3314b))
* **lifecycle-operator:** move API HUB version to v1beta1 ([#2772](https://github.com/keptn/lifecycle-toolkit/issues/2772)) ([5d7ebbd](https://github.com/keptn/lifecycle-toolkit/commit/5d7ebbdc2ef55714e62dd8ad8b600a1098f9adef))
* **lifecycle-operator:** propagate KeptnAppVersion Context Metadata to KeptnWorkloadVersion span ([#2859](https://github.com/keptn/lifecycle-toolkit/issues/2859)) ([5c14bf5](https://github.com/keptn/lifecycle-toolkit/commit/5c14bf59e813db10f953ea019c8d61d7ec2e8f6d))
* **lifecycle-operator:** propagate metadata from deployment annotations ([#2832](https://github.com/keptn/lifecycle-toolkit/issues/2832)) ([6f700ce](https://github.com/keptn/lifecycle-toolkit/commit/6f700ce453ff1c26f353bc5e109c8b3e1840b283))
* **lifecycle-operator:** rename CONTEXT to KEPTN_CONTEXT in task runtimes ([#2521](https://github.com/keptn/lifecycle-toolkit/issues/2521)) ([a7322bd](https://github.com/keptn/lifecycle-toolkit/commit/a7322bd9266fa1589d77b06675d70d1a9e6c29ac))
* **lifecycle-operator:** support imagePullSecrets in KeptnTaskDefinitions ([#2549](https://github.com/keptn/lifecycle-toolkit/issues/2549)) ([c71d868](https://github.com/keptn/lifecycle-toolkit/commit/c71d86864ba48a82d9f66d57e93521d99c426970))
* **lifecycle-operator:** support linked spans in KeptnAppVersion ([#2833](https://github.com/keptn/lifecycle-toolkit/issues/2833)) ([36e19b2](https://github.com/keptn/lifecycle-toolkit/commit/36e19b2a9f9706722a05bd13e46340bd68922265))


### Bug Fixes

* **helm-chart:** remove double templating of annotations ([#2770](https://github.com/keptn/lifecycle-toolkit/issues/2770)) ([b7a1d29](https://github.com/keptn/lifecycle-toolkit/commit/b7a1d291223eddd9ac83425c71c8c1a515f25f58))
* **lifecycle-operator:** adopt KeptnApp name from either Keptn or k8s label ([#2440](https://github.com/keptn/lifecycle-toolkit/issues/2440)) ([3185943](https://github.com/keptn/lifecycle-toolkit/commit/318594309af9653253f84b35f86e9b6675c572ca))
* **lifecycle-operator:** duplicate version in project file ([#2767](https://github.com/keptn/lifecycle-toolkit/issues/2767)) ([c7ed8a6](https://github.com/keptn/lifecycle-toolkit/commit/c7ed8a69c9af658606761261216e6c00bae5ffa8))
* **lifecycle-operator:** fix app deployment span structure ([#2352](https://github.com/keptn/lifecycle-toolkit/issues/2352)) ([64c1919](https://github.com/keptn/lifecycle-toolkit/commit/64c1919f43378650a6677b3b5baa91776e96bef9))
* **lifecycle-operator:** introduce separate controller for removing scheduling gates from pods ([#2946](https://github.com/keptn/lifecycle-toolkit/issues/2946)) ([9fa3770](https://github.com/keptn/lifecycle-toolkit/commit/9fa3770bbf3a2a2374993144df4fa469837aa7a0))
* **lifecycle-operator:** make sure spec of KeptnWorkloadVersion is consistent with KeptnWorkload ([#2926](https://github.com/keptn/lifecycle-toolkit/issues/2926)) ([f2f8c29](https://github.com/keptn/lifecycle-toolkit/commit/f2f8c296a1b7f9746c55c2781c22727c62a2bab3))


### Other

* adapt examples to use v1beta1 API resources ([#2868](https://github.com/keptn/lifecycle-toolkit/issues/2868)) ([587773f](https://github.com/keptn/lifecycle-toolkit/commit/587773fbea63dbf575879bd3bec447fe55ac4311))
* adapt helm charts to the new Keptn naming ([#2564](https://github.com/keptn/lifecycle-toolkit/issues/2564)) ([9ee4583](https://github.com/keptn/lifecycle-toolkit/commit/9ee45834bfa4dcedcbe99362d5d58b9febe3caae))
* add config for spell checker action, fix typos ([#2443](https://github.com/keptn/lifecycle-toolkit/issues/2443)) ([eac178f](https://github.com/keptn/lifecycle-toolkit/commit/eac178f650962208449553086d54d26d27fa4da3))
* add KeptnApp migration script ([#2959](https://github.com/keptn/lifecycle-toolkit/issues/2959)) ([7311422](https://github.com/keptn/lifecycle-toolkit/commit/7311422791f5429fa77ac18da857e4f14b502eba))
* clean up deprecated API resources from helm charts ([#2800](https://github.com/keptn/lifecycle-toolkit/issues/2800)) ([43d092d](https://github.com/keptn/lifecycle-toolkit/commit/43d092d17f852d60f4e29a2887128b33a3fd2764))
* clean up unused volumes ([#2638](https://github.com/keptn/lifecycle-toolkit/issues/2638)) ([32be4db](https://github.com/keptn/lifecycle-toolkit/commit/32be4db7ed35676967148fdc93cbe1a378220afa))
* **helm-chart:** generate umbrella chart lock ([#2391](https://github.com/keptn/lifecycle-toolkit/issues/2391)) ([55e12d4](https://github.com/keptn/lifecycle-toolkit/commit/55e12d4a6c3b5cd0fbb2cd6b8b8d29f2b7c8c500))
* **lifecycle-operator:** adapt KeptnAppVersionReconciler to make use of PhaseHandler interface ([#2463](https://github.com/keptn/lifecycle-toolkit/issues/2463)) ([2511e05](https://github.com/keptn/lifecycle-toolkit/commit/2511e05cefe8876c0bb67fbf9763213ef81a81a0))
* **lifecycle-operator:** introduce PhaseHandler interface to be used in KeptnWorkloadVersion reconciler ([#2450](https://github.com/keptn/lifecycle-toolkit/issues/2450)) ([7d4b431](https://github.com/keptn/lifecycle-toolkit/commit/7d4b431af5a6e9deec03784b04267d9711c93f17))
* **lifecycle-operator:** introduce v1beta1 lifecycle API ([#2640](https://github.com/keptn/lifecycle-toolkit/issues/2640)) ([11b7ea2](https://github.com/keptn/lifecycle-toolkit/commit/11b7ea2bbf6fc22dc781fdf1e7afdde1b6b54035))
* **lifecycle-operator:** make evaluationhandler injectable in `KeptnWorkloadVersionController` ([#2299](https://github.com/keptn/lifecycle-toolkit/issues/2299)) ([211b272](https://github.com/keptn/lifecycle-toolkit/commit/211b2727cdce51378a33ce92775f231e2b025117))
* **lifecycle-operator:** make evaluationhandler injectable in KeptnAppVersionController ([#2402](https://github.com/keptn/lifecycle-toolkit/issues/2402)) ([a060859](https://github.com/keptn/lifecycle-toolkit/commit/a06085954ff3fd508f6c0ebec806df78babd8dc4))
* **lifecycle-operator:** propagate Context Metadata to KeptnAppVersion ([#2848](https://github.com/keptn/lifecycle-toolkit/issues/2848)) ([5fac158](https://github.com/keptn/lifecycle-toolkit/commit/5fac158a7ffed67f7502fe03683138d717ea1acd))
* **lifecycle-operator:** refactor `WorkloadVersionReconciler` ([#2417](https://github.com/keptn/lifecycle-toolkit/issues/2417)) ([c41f909](https://github.com/keptn/lifecycle-toolkit/commit/c41f909044a40485bee07ddcaa59a0d9924a1bf1))
* **lifecycle-operator:** remove `OTEL_COLLECTOR_URL` env var in favour of related option in `KeptnConfig` CRD ([#2593](https://github.com/keptn/lifecycle-toolkit/issues/2593)) ([df0a5b4](https://github.com/keptn/lifecycle-toolkit/commit/df0a5b4a9ec04326a044bc5a79a6babf54a13363))
* **lifecycle-operator:** remove pre post deploy task evaluation v1beta1 ([#2782](https://github.com/keptn/lifecycle-toolkit/issues/2782)) ([6e992d7](https://github.com/keptn/lifecycle-toolkit/commit/6e992d72313792d7e3024fd99599ca8658c98737))
* **lifecycle-operator:** renamed TracerFactory to tracerFactory workloadversion ([#2428](https://github.com/keptn/lifecycle-toolkit/issues/2428)) ([8c10e38](https://github.com/keptn/lifecycle-toolkit/commit/8c10e38435fd41079b9853b4e7f2039549ff80b9))
* **lifecycle-operator:** split controllers/common package into multiple ([#2386](https://github.com/keptn/lifecycle-toolkit/issues/2386)) ([cbda641](https://github.com/keptn/lifecycle-toolkit/commit/cbda6410e12e24cb8af3754a6f396e4b99164e14))
* re-generate CRD manifests ([#2830](https://github.com/keptn/lifecycle-toolkit/issues/2830)) ([c0b1942](https://github.com/keptn/lifecycle-toolkit/commit/c0b1942e8f2ddd177776ed681432016d81805724))
* remove performance-test workflow and relative makefile entry ([#2706](https://github.com/keptn/lifecycle-toolkit/issues/2706)) ([8599276](https://github.com/keptn/lifecycle-toolkit/commit/859927698453bbd1f718b347c73f70da6596713f))
* rename Keptn default namespace to 'keptn-system' ([#2565](https://github.com/keptn/lifecycle-toolkit/issues/2565)) ([aec1148](https://github.com/keptn/lifecycle-toolkit/commit/aec11489451ab1b0bcd69a6b90b0d45f69c5df7c))
* rename KLT to Keptn ([#2554](https://github.com/keptn/lifecycle-toolkit/issues/2554)) ([15b0ac0](https://github.com/keptn/lifecycle-toolkit/commit/15b0ac0b36b8081b85b63f36e94b00065bcc8b22))
* revert helm charts bump ([#2806](https://github.com/keptn/lifecycle-toolkit/issues/2806)) ([2e85214](https://github.com/keptn/lifecycle-toolkit/commit/2e85214ecd6112e9f9af750d9bde2d491dc8ae73))
* update to crd generator to v0.0.10 ([#2329](https://github.com/keptn/lifecycle-toolkit/issues/2329)) ([525ae03](https://github.com/keptn/lifecycle-toolkit/commit/525ae03725f374d0b056c6da2fd7af3e4062f7a2))
* upgrade helm chart versions ([#2801](https://github.com/keptn/lifecycle-toolkit/issues/2801)) ([ad26093](https://github.com/keptn/lifecycle-toolkit/commit/ad2609373c4819fc560766e64bc032fcfd801889))


### Docs

* remove Scarf transparent pixels ([#2590](https://github.com/keptn/lifecycle-toolkit/issues/2590)) ([95851fa](https://github.com/keptn/lifecycle-toolkit/commit/95851fa52cb3a6565a4b52ae0e8b00dcc9861a3b))


### Dependency Updates

* update dependency kubernetes-sigs/controller-tools to v0.14.0 ([#2797](https://github.com/keptn/lifecycle-toolkit/issues/2797)) ([71f20a6](https://github.com/keptn/lifecycle-toolkit/commit/71f20a63f8e307d6e94c9c2df79a1258ab147ede))
* update dependency kubernetes-sigs/kustomize to v5.3.0 ([#2659](https://github.com/keptn/lifecycle-toolkit/issues/2659)) ([8877921](https://github.com/keptn/lifecycle-toolkit/commit/8877921b8be3052ce61a4f8decd96537c93df27a))
* update ghcr.io/keptn/deno-runtime docker tag to v2 ([#2969](https://github.com/keptn/lifecycle-toolkit/issues/2969)) ([ea3e77d](https://github.com/keptn/lifecycle-toolkit/commit/ea3e77da83cb1d170e10329ecafcc837a03ee095))
* update ghcr.io/keptn/python-runtime docker tag to v1.0.2 ([#2968](https://github.com/keptn/lifecycle-toolkit/issues/2968)) ([ae7d394](https://github.com/keptn/lifecycle-toolkit/commit/ae7d3943c8aee315273eda0c13909a1cc8cb4b52))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to 0677987 ([#2429](https://github.com/keptn/lifecycle-toolkit/issues/2429)) ([f718913](https://github.com/keptn/lifecycle-toolkit/commit/f7189131cefcc6fe9a42a560d696ca019afc541f))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to 964fd25 ([#2485](https://github.com/keptn/lifecycle-toolkit/issues/2485)) ([f7124d0](https://github.com/keptn/lifecycle-toolkit/commit/f7124d034dd6e1558581de35f449bf08b2c73bab))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to d2c3e14 ([#2375](https://github.com/keptn/lifecycle-toolkit/issues/2375)) ([b945bf8](https://github.com/keptn/lifecycle-toolkit/commit/b945bf875e435ab713d5b37cf8c0415948942bf1))
* update golang.org/x/exp digest to 1b97071 ([#2875](https://github.com/keptn/lifecycle-toolkit/issues/2875)) ([20f5705](https://github.com/keptn/lifecycle-toolkit/commit/20f5705141e252afbe76834be739f305ac3b273a))
* update golang.org/x/exp digest to 2c58cdc ([#2971](https://github.com/keptn/lifecycle-toolkit/issues/2971)) ([fddbce7](https://github.com/keptn/lifecycle-toolkit/commit/fddbce72ea68e3f507adf61d76f259eab4303cdb))
* update keptn/common helm chart to 0.1.3 ([#2831](https://github.com/keptn/lifecycle-toolkit/issues/2831)) ([29187fa](https://github.com/keptn/lifecycle-toolkit/commit/29187fa7eeab148b7188b4c3f05317cc291c15e4))
* update kubernetes packages to v0.28.5 (patch) ([#2714](https://github.com/keptn/lifecycle-toolkit/issues/2714)) ([192c0b1](https://github.com/keptn/lifecycle-toolkit/commit/192c0b16fc0852dca572448d8caeb113b0e21d40))
* update kubernetes packages to v0.28.6 (patch) ([#2827](https://github.com/keptn/lifecycle-toolkit/issues/2827)) ([da080fa](https://github.com/keptn/lifecycle-toolkit/commit/da080fafadef25028f9e4b1a78d8a862e58b47e7))
* update module github.com/argoproj/argo-rollouts to v1.6.2 ([#2411](https://github.com/keptn/lifecycle-toolkit/issues/2411)) ([9e9d731](https://github.com/keptn/lifecycle-toolkit/commit/9e9d731084ee453c26a133f32cf82d58b275b4da))
* update module github.com/argoproj/argo-rollouts to v1.6.3 ([#2652](https://github.com/keptn/lifecycle-toolkit/issues/2652)) ([e386ec6](https://github.com/keptn/lifecycle-toolkit/commit/e386ec643fa7a202fda32d5f1126581b7c084109))
* update module github.com/argoproj/argo-rollouts to v1.6.4 ([#2679](https://github.com/keptn/lifecycle-toolkit/issues/2679)) ([95380bb](https://github.com/keptn/lifecycle-toolkit/commit/95380bb523e71f63b3f7d0769934b85931b5fec8))
* update module github.com/argoproj/argo-rollouts to v1.6.5 ([#2892](https://github.com/keptn/lifecycle-toolkit/issues/2892)) ([7c8b14f](https://github.com/keptn/lifecycle-toolkit/commit/7c8b14f8c09be6995eb341582177dfed8038b7cd))
* update module github.com/cloudevents/sdk-go/v2 to v2.15.0 ([#2845](https://github.com/keptn/lifecycle-toolkit/issues/2845)) ([22dd509](https://github.com/keptn/lifecycle-toolkit/commit/22dd5093e263979f466b08f20f72a8763528c957))
* update module github.com/go-logr/logr to v1.4.1 ([#2726](https://github.com/keptn/lifecycle-toolkit/issues/2726)) ([3598999](https://github.com/keptn/lifecycle-toolkit/commit/3598999e1cfce6ee528fb5fb777c0b7b7c21678a))
* update module github.com/keptn/lifecycle-toolkit/keptn-cert-manager to v0.8.0 ([#2534](https://github.com/keptn/lifecycle-toolkit/issues/2534)) ([94007a0](https://github.com/keptn/lifecycle-toolkit/commit/94007a03cd9bd7e09bad79feb12b27b615a75151))
* update module github.com/keptn/lifecycle-toolkit/keptn-cert-manager to v2.0.0 ([#2668](https://github.com/keptn/lifecycle-toolkit/issues/2668)) ([be6523b](https://github.com/keptn/lifecycle-toolkit/commit/be6523b39b431e9c1cfac51ac553c4c71e0ad4a1))
* update module github.com/onsi/ginkgo/v2 to v2.13.1 ([#2486](https://github.com/keptn/lifecycle-toolkit/issues/2486)) ([14dcd27](https://github.com/keptn/lifecycle-toolkit/commit/14dcd27f4b1e67803332a8dc53b42b67c7bb2030))
* update module github.com/onsi/ginkgo/v2 to v2.13.2 ([#2624](https://github.com/keptn/lifecycle-toolkit/issues/2624)) ([197c7db](https://github.com/keptn/lifecycle-toolkit/commit/197c7db78a5baf754e773ab79c5cd6a5ab9c5591))
* update module github.com/onsi/ginkgo/v2 to v2.14.0 ([#2808](https://github.com/keptn/lifecycle-toolkit/issues/2808)) ([17b0cb1](https://github.com/keptn/lifecycle-toolkit/commit/17b0cb1314778f5f1b65f4d1029ecca41bb50d3a))
* update module github.com/onsi/ginkgo/v2 to v2.15.0 ([#2855](https://github.com/keptn/lifecycle-toolkit/issues/2855)) ([1c4f410](https://github.com/keptn/lifecycle-toolkit/commit/1c4f410f5571f02254eda4c5027c8a5e3822b28e))
* update module github.com/onsi/gomega to v1.29.0 ([#2379](https://github.com/keptn/lifecycle-toolkit/issues/2379)) ([98e420a](https://github.com/keptn/lifecycle-toolkit/commit/98e420a4b2138e90e2f87c399139bd8e5a90cef5))
* update module github.com/onsi/gomega to v1.30.0 ([#2478](https://github.com/keptn/lifecycle-toolkit/issues/2478)) ([398b949](https://github.com/keptn/lifecycle-toolkit/commit/398b9493414ab5d70bd76d94b038456e58813e70))
* update module github.com/onsi/gomega to v1.31.1 ([#2856](https://github.com/keptn/lifecycle-toolkit/issues/2856)) ([d0817a7](https://github.com/keptn/lifecycle-toolkit/commit/d0817a7118e58af5326a43f1a059f2eddfa36215))
* update module github.com/prometheus/client_golang to v1.18.0 ([#2764](https://github.com/keptn/lifecycle-toolkit/issues/2764)) ([67fa60b](https://github.com/keptn/lifecycle-toolkit/commit/67fa60b8581fee0b6200f8f877b396a39df32d58))
* update module golang.org/x/net to v0.18.0 ([#2479](https://github.com/keptn/lifecycle-toolkit/issues/2479)) ([6ddd8ee](https://github.com/keptn/lifecycle-toolkit/commit/6ddd8eeec5eabb0c67b5a7b9965a34368f62c8d5))
* update module golang.org/x/net to v0.19.0 ([#2619](https://github.com/keptn/lifecycle-toolkit/issues/2619)) ([af2d0a5](https://github.com/keptn/lifecycle-toolkit/commit/af2d0a509b670792e06e2d05ab4be261d3bb54f4))
* update module golang.org/x/net to v0.20.0 ([#2786](https://github.com/keptn/lifecycle-toolkit/issues/2786)) ([8294c7b](https://github.com/keptn/lifecycle-toolkit/commit/8294c7b471d7f4d33961513e056c36ba14c940c7))
* update module google.golang.org/grpc to v1.60.0 ([#2681](https://github.com/keptn/lifecycle-toolkit/issues/2681)) ([7dd45a3](https://github.com/keptn/lifecycle-toolkit/commit/7dd45a33fba8fd3235e40202ece9057cef429bb6))
* update module google.golang.org/grpc to v1.60.1 ([#2724](https://github.com/keptn/lifecycle-toolkit/issues/2724)) ([31d69dd](https://github.com/keptn/lifecycle-toolkit/commit/31d69dd33df76f0a5f9b2d46af822e5f43e681a5))
* update module google.golang.org/grpc to v1.61.0 ([#2888](https://github.com/keptn/lifecycle-toolkit/issues/2888)) ([7a56cbd](https://github.com/keptn/lifecycle-toolkit/commit/7a56cbd1f528bb73c1070611d6b28005c875fe36))
* update module k8s.io/apimachinery to v0.28.4 ([#2514](https://github.com/keptn/lifecycle-toolkit/issues/2514)) ([c25c236](https://github.com/keptn/lifecycle-toolkit/commit/c25c236ecc37dc1f33b75a172cee2422bdb416ba))
* update opentelemetry-go monorepo (minor) ([#2487](https://github.com/keptn/lifecycle-toolkit/issues/2487)) ([a5d492a](https://github.com/keptn/lifecycle-toolkit/commit/a5d492abe1757bcac0259ae059d137d8afa6d57a))
* update opentelemetry-go monorepo (minor) ([#2535](https://github.com/keptn/lifecycle-toolkit/issues/2535)) ([7e3f5e6](https://github.com/keptn/lifecycle-toolkit/commit/7e3f5e6a14edeb1063765c3122f90e4c7659c943))
* update opentelemetry-go monorepo (minor) ([#2865](https://github.com/keptn/lifecycle-toolkit/issues/2865)) ([be0ecde](https://github.com/keptn/lifecycle-toolkit/commit/be0ecde8088af5e4a43d01951f6b7f354267308d))

## [0.8.3](https://github.com/keptn/lifecycle-toolkit/compare/lifecycle-operator-v0.8.2...lifecycle-operator-v0.8.3) (2023-10-31)


### Features

* adapt code to use KeptnWorkloadVersion instead of KeptnWorkloadInstance ([#2255](https://github.com/keptn/lifecycle-toolkit/issues/2255)) ([c06fae1](https://github.com/keptn/lifecycle-toolkit/commit/c06fae13daa2aa98a3daf71abafe0e8ce4e5f4a3))
* add test and lint cmd to makefiles ([#2176](https://github.com/keptn/lifecycle-toolkit/issues/2176)) ([c55e0a9](https://github.com/keptn/lifecycle-toolkit/commit/c55e0a9f368c82ad3032eb676edd59e68b29fad6))
* create new Keptn umbrella Helm chart ([#2214](https://github.com/keptn/lifecycle-toolkit/issues/2214)) ([41bd47b](https://github.com/keptn/lifecycle-toolkit/commit/41bd47b7748c4d645243a4dae165651bbfd3533f))
* generalize helm chart ([#2282](https://github.com/keptn/lifecycle-toolkit/issues/2282)) ([81334eb](https://github.com/keptn/lifecycle-toolkit/commit/81334ebec4d8afda27902b6e854c4c637a3daa87))
* **lifecycle-operator:** add helm chart for lifecycle operator ([#2200](https://github.com/keptn/lifecycle-toolkit/issues/2200)) ([9f0853f](https://github.com/keptn/lifecycle-toolkit/commit/9f0853fca2b92c9636e76dc77666148d86078af7))
* **lifecycle-operator:** automatically decide for scheduler installation based on k8s version ([#2212](https://github.com/keptn/lifecycle-toolkit/issues/2212)) ([25976ea](https://github.com/keptn/lifecycle-toolkit/commit/25976ead3fb1d95634ee3a00a7d37b3e98b2ec06))
* **lifecycle-operator:** introduce functions for SchedulingGates functionality ([#2140](https://github.com/keptn/lifecycle-toolkit/issues/2140)) ([b40503e](https://github.com/keptn/lifecycle-toolkit/commit/b40503ef6c867033994383767ad5149eb08ab8da))
* **lifecycle-operator:** introduce metric showing readiness of operator ([#2152](https://github.com/keptn/lifecycle-toolkit/issues/2152)) ([c0e3f48](https://github.com/keptn/lifecycle-toolkit/commit/c0e3f48dd0e34084c7d2d8e469e73c3f2865ea48))
* **lifecycle-operator:** introduce option to enable lifecycle orchestration only for specific namespaces ([#2244](https://github.com/keptn/lifecycle-toolkit/issues/2244)) ([12caf03](https://github.com/keptn/lifecycle-toolkit/commit/12caf031d336c7a34e495b36daccb5ec3524ae49))
* **lifecycle-operator:** introduce v1alpha4 API version for KeptnWorkloadInstance ([#2250](https://github.com/keptn/lifecycle-toolkit/issues/2250)) ([d95dc10](https://github.com/keptn/lifecycle-toolkit/commit/d95dc1037ce22296aff65d6ad6fa420e96172d5d))
* **metrics-operator:** add support for user-friendly duration string for specifying time frame ([#2147](https://github.com/keptn/lifecycle-toolkit/issues/2147)) ([34e5384](https://github.com/keptn/lifecycle-toolkit/commit/34e5384bb434836658a7bf375c4fc8de765023b6))
* move helm docs into values files ([#2281](https://github.com/keptn/lifecycle-toolkit/issues/2281)) ([bd1a37b](https://github.com/keptn/lifecycle-toolkit/commit/bd1a37b324e25d07e88e7c4d1ad8150a7b3d4dac))
* support scheduling gates in integration tests ([#2149](https://github.com/keptn/lifecycle-toolkit/issues/2149)) ([3ff67d5](https://github.com/keptn/lifecycle-toolkit/commit/3ff67d5632f287613f337c7418aa5e28e616d536))


### Bug Fixes

* change klt to keptn for annotations and certs ([#2229](https://github.com/keptn/lifecycle-toolkit/issues/2229)) ([608a75e](https://github.com/keptn/lifecycle-toolkit/commit/608a75ebb73006b82b370b40e86b83ee874764e8))
* helm charts image registry, image pull policy and install action ([#2361](https://github.com/keptn/lifecycle-toolkit/issues/2361)) ([76ed884](https://github.com/keptn/lifecycle-toolkit/commit/76ed884498971c87c48cdab6fea822dfcf3e6e2f))
* **lifecycle-operator:** make sure the CloudEvents endpoint from the KeptnConfig is applied ([#2289](https://github.com/keptn/lifecycle-toolkit/issues/2289)) ([b5d9fc0](https://github.com/keptn/lifecycle-toolkit/commit/b5d9fc0b182ff3d1a777dabec74314df3157edbb))
* **lifecycle-operator:** remove hardcoded keptn namespace ([#2141](https://github.com/keptn/lifecycle-toolkit/issues/2141)) ([f10b447](https://github.com/keptn/lifecycle-toolkit/commit/f10b4470bdc4346e6ccd17fecc92c8bd5675c7e5))
* update kustomization.yaml to avoid usage of deprecated patches/configs ([#2004](https://github.com/keptn/lifecycle-toolkit/issues/2004)) ([8d70fac](https://github.com/keptn/lifecycle-toolkit/commit/8d70fac1f9469107257976659fb8b7b414d0455b))
* update outdated CRDs in helm chart templates ([#2123](https://github.com/keptn/lifecycle-toolkit/issues/2123)) ([34c9d11](https://github.com/keptn/lifecycle-toolkit/commit/34c9d11a1dd34b181d2d1a9e5c61fd75638aaebf))


### Other

* adapt Makefile command to run unit tests ([#2072](https://github.com/keptn/lifecycle-toolkit/issues/2072)) ([2db2569](https://github.com/keptn/lifecycle-toolkit/commit/2db25691748beedbb02ed92806d327067c422285))
* **lifecycle-operator:** improve logging ([#2253](https://github.com/keptn/lifecycle-toolkit/issues/2253)) ([8dd3394](https://github.com/keptn/lifecycle-toolkit/commit/8dd3394087cf0d445ec0b3bad0a54242ad9f4f26))
* **lifecycle-operator:** refactor pod mutating webhook ([#2233](https://github.com/keptn/lifecycle-toolkit/issues/2233)) ([c2cc89a](https://github.com/keptn/lifecycle-toolkit/commit/c2cc89a3ad3ac0fef3410adb1c0b24aa10e8dc66))
* **lifecycle-operator:** remove direct dependency on jsonpatch ([#2187](https://github.com/keptn/lifecycle-toolkit/issues/2187)) ([d7fce2a](https://github.com/keptn/lifecycle-toolkit/commit/d7fce2a320bd34cd41d564e0d528675e5a1cd93e))
* **lifecycle-operator:** remove spans created by webhook ([#2331](https://github.com/keptn/lifecycle-toolkit/issues/2331)) ([9f21fb6](https://github.com/keptn/lifecycle-toolkit/commit/9f21fb62284e806f6356341315873f98e0c4fd29))
* **lifecycle-operator:** remove spans for reconciliation loops, adjust log levels ([#2310](https://github.com/keptn/lifecycle-toolkit/issues/2310)) ([d73008c](https://github.com/keptn/lifecycle-toolkit/commit/d73008ccaa5e028f1551392b9c68a4ea0315350e))
* regenerate CRDs ([#2074](https://github.com/keptn/lifecycle-toolkit/issues/2074)) ([63f5dc1](https://github.com/keptn/lifecycle-toolkit/commit/63f5dc1bc3dfd696de3730ed3949c0f99abdecc0))
* update k8s version ([#1701](https://github.com/keptn/lifecycle-toolkit/issues/1701)) ([010d7cd](https://github.com/keptn/lifecycle-toolkit/commit/010d7cd48c2e26993e25de607f30b40513c9cd61))
* update release please config to work with umbrella chart ([#2357](https://github.com/keptn/lifecycle-toolkit/issues/2357)) ([6ff3a5f](https://github.com/keptn/lifecycle-toolkit/commit/6ff3a5f64e394504fd5e7b67f0ac0a608428c1be))


### Docs

* adapt KeptnTask example to changes in API  ([#2124](https://github.com/keptn/lifecycle-toolkit/issues/2124)) ([bcc64e8](https://github.com/keptn/lifecycle-toolkit/commit/bcc64e814d7735bc330d2d0b3b52eccf7a51dbbe))


### Dependency Updates

* update dependency kubernetes-sigs/kustomize to v5.2.1 ([#2308](https://github.com/keptn/lifecycle-toolkit/issues/2308)) ([6653a47](https://github.com/keptn/lifecycle-toolkit/commit/6653a47d4156c0e60aa471f11a643a2664669023))
* update ghcr.io/keptn/deno-runtime docker tag to v1.0.2 ([#2367](https://github.com/keptn/lifecycle-toolkit/issues/2367)) ([6c17203](https://github.com/keptn/lifecycle-toolkit/commit/6c1720356fab6b4a9d1c0dae30e76e6d5c135c70))
* update ghcr.io/keptn/python-runtime docker tag to v1.0.1 ([#2368](https://github.com/keptn/lifecycle-toolkit/issues/2368)) ([134191a](https://github.com/keptn/lifecycle-toolkit/commit/134191a523c6d278771ad1f3421e4ae68dad4de9))
* update ghcr.io/keptn/scheduler docker tag to v0.8.3 ([#2374](https://github.com/keptn/lifecycle-toolkit/issues/2374)) ([16a4a14](https://github.com/keptn/lifecycle-toolkit/commit/16a4a147905fe19b319010e880730ee46e6c5965))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to 010d7cd ([#2106](https://github.com/keptn/lifecycle-toolkit/issues/2106)) ([2ef614a](https://github.com/keptn/lifecycle-toolkit/commit/2ef614ad08dbeed1301889ed560375a2bb9e737c))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to 066be3e ([#2274](https://github.com/keptn/lifecycle-toolkit/issues/2274)) ([c6d9c52](https://github.com/keptn/lifecycle-toolkit/commit/c6d9c524afa61e7c87553b89ebab1a2b8daa1438))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to 099a457 ([#2169](https://github.com/keptn/lifecycle-toolkit/issues/2169)) ([643ae4e](https://github.com/keptn/lifecycle-toolkit/commit/643ae4e69ac527a342eed20c0e078c6b0e8cdd97))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to 3077e31 ([#2313](https://github.com/keptn/lifecycle-toolkit/issues/2313)) ([cf52945](https://github.com/keptn/lifecycle-toolkit/commit/cf529455f2e99119e48ba433d28e8aecc31cad00))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to 4342d33 ([#2177](https://github.com/keptn/lifecycle-toolkit/issues/2177)) ([2b5267c](https://github.com/keptn/lifecycle-toolkit/commit/2b5267c0a88b7f68167314d624c54453a326b5ce))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to 469578e ([#2038](https://github.com/keptn/lifecycle-toolkit/issues/2038)) ([d240e56](https://github.com/keptn/lifecycle-toolkit/commit/d240e56fbc0b42caad04d8393ec59e55f1013efa))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to 5efa650 ([#2155](https://github.com/keptn/lifecycle-toolkit/issues/2155)) ([fa8c891](https://github.com/keptn/lifecycle-toolkit/commit/fa8c8912825ad0bbc3f75b7a037e856bac6dad93))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to 608a75e ([#2231](https://github.com/keptn/lifecycle-toolkit/issues/2231)) ([26ff714](https://github.com/keptn/lifecycle-toolkit/commit/26ff714800bb605bfe58b61da432237132edf072))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to 6566e7d ([#2143](https://github.com/keptn/lifecycle-toolkit/issues/2143)) ([9e7fe83](https://github.com/keptn/lifecycle-toolkit/commit/9e7fe8353dd8c84fae96081c2bb7522ab7ff7f5a))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to 8dd3394 ([#2271](https://github.com/keptn/lifecycle-toolkit/issues/2271)) ([b29fc99](https://github.com/keptn/lifecycle-toolkit/commit/b29fc999aef2c214b7b45a1161b226e85e3eaffe))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to a15b038 ([#2205](https://github.com/keptn/lifecycle-toolkit/issues/2205)) ([1592926](https://github.com/keptn/lifecycle-toolkit/commit/1592926d6c70062cd632969f991531aa9b00f0de))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to a656512 ([#2230](https://github.com/keptn/lifecycle-toolkit/issues/2230)) ([f11fdb9](https://github.com/keptn/lifecycle-toolkit/commit/f11fdb959b4e207d3704361870d515f61ad92360))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to b2853f9 ([#2094](https://github.com/keptn/lifecycle-toolkit/issues/2094)) ([b9019cd](https://github.com/keptn/lifecycle-toolkit/commit/b9019cd96a161c4e0c4dd08e3ddbabd152ea921c))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to c1166ff ([#2242](https://github.com/keptn/lifecycle-toolkit/issues/2242)) ([aa53137](https://github.com/keptn/lifecycle-toolkit/commit/aa531375032468a6e0d1b3a9f6eb3e6e9b0c998b))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to f2f3a0c ([#2132](https://github.com/keptn/lifecycle-toolkit/issues/2132)) ([2039d36](https://github.com/keptn/lifecycle-toolkit/commit/2039d36f427e22bfe692fade207319747ee15083))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to f2f8dfe ([#2297](https://github.com/keptn/lifecycle-toolkit/issues/2297)) ([e13b9be](https://github.com/keptn/lifecycle-toolkit/commit/e13b9be3217fdd5bf3a646dd3d6ba49438cbb9e6))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to f3bbb96 ([#2342](https://github.com/keptn/lifecycle-toolkit/issues/2342)) ([89ddb2f](https://github.com/keptn/lifecycle-toolkit/commit/89ddb2f427561bbc41ea2e4b762ac3a14aab3bc5))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to fda2315 ([#2300](https://github.com/keptn/lifecycle-toolkit/issues/2300)) ([bffbaf2](https://github.com/keptn/lifecycle-toolkit/commit/bffbaf2edf4710e085db1ee956b3ccc1b6599275))
* update kubernetes packages (patch) ([#2102](https://github.com/keptn/lifecycle-toolkit/issues/2102)) ([b2853f9](https://github.com/keptn/lifecycle-toolkit/commit/b2853f9ecdfb4b7b81d0b88cf782b82c9958c5cb))
* update module github.com/argoproj/argo-rollouts to v1.6.0 ([#2064](https://github.com/keptn/lifecycle-toolkit/issues/2064)) ([d5c428a](https://github.com/keptn/lifecycle-toolkit/commit/d5c428a7e31c00362b8280da5acd91ade89c1fa8))
* update module github.com/go-logr/logr to v1.3.0 ([#2346](https://github.com/keptn/lifecycle-toolkit/issues/2346)) ([bc06204](https://github.com/keptn/lifecycle-toolkit/commit/bc06204b97c765d0f5664fd66f441af86f21e191))
* update module github.com/onsi/ginkgo/v2 to v2.12.1 ([#2156](https://github.com/keptn/lifecycle-toolkit/issues/2156)) ([dbf2867](https://github.com/keptn/lifecycle-toolkit/commit/dbf2867133067b162e82b71b6547c3dfac95d0af))
* update module github.com/onsi/ginkgo/v2 to v2.13.0 ([#2272](https://github.com/keptn/lifecycle-toolkit/issues/2272)) ([0df464d](https://github.com/keptn/lifecycle-toolkit/commit/0df464dd8e4fc7729deeb5bae4938b236902d661))
* update module github.com/onsi/gomega to v1.28.0 ([#2209](https://github.com/keptn/lifecycle-toolkit/issues/2209)) ([c0726d0](https://github.com/keptn/lifecycle-toolkit/commit/c0726d0b0e9d9732123aaf8b1ad012bc24672b84))
* update module github.com/onsi/gomega to v1.28.1 ([#2343](https://github.com/keptn/lifecycle-toolkit/issues/2343)) ([64b1508](https://github.com/keptn/lifecycle-toolkit/commit/64b1508f0e383aa7fbc406e17e2cc66546601e53))
* update module github.com/prometheus/client_golang to v1.17.0 ([#2207](https://github.com/keptn/lifecycle-toolkit/issues/2207)) ([de8b958](https://github.com/keptn/lifecycle-toolkit/commit/de8b9587cb95b1ee9c2be7a66320d284491102d9))
* update module golang.org/x/net to v0.15.0 ([#2065](https://github.com/keptn/lifecycle-toolkit/issues/2065)) ([50ce9c0](https://github.com/keptn/lifecycle-toolkit/commit/50ce9c09914f505ffaf33eee41564afa65661215))
* update module golang.org/x/net to v0.16.0 ([#2249](https://github.com/keptn/lifecycle-toolkit/issues/2249)) ([e89ea71](https://github.com/keptn/lifecycle-toolkit/commit/e89ea71bc1a2d69828179c64ffe3c34ce359dd94))
* update module golang.org/x/net to v0.17.0 ([#2267](https://github.com/keptn/lifecycle-toolkit/issues/2267)) ([8443874](https://github.com/keptn/lifecycle-toolkit/commit/8443874254cda9e5f4c662cab1a3e5e3b3277435))
* update module google.golang.org/grpc to v1.58.0 ([#2066](https://github.com/keptn/lifecycle-toolkit/issues/2066)) ([6fae5a7](https://github.com/keptn/lifecycle-toolkit/commit/6fae5a7ebf356625b4754b7890f7c71dbb4ac0a6))
* update module google.golang.org/grpc to v1.58.1 ([#2115](https://github.com/keptn/lifecycle-toolkit/issues/2115)) ([d08df40](https://github.com/keptn/lifecycle-toolkit/commit/d08df40188bc633037c49a1468a70eefc960a4a1))
* update module google.golang.org/grpc to v1.58.2 ([#2163](https://github.com/keptn/lifecycle-toolkit/issues/2163)) ([5efa650](https://github.com/keptn/lifecycle-toolkit/commit/5efa6502403daa37bdfc51fa8600da6b1f845ac2))
* update module google.golang.org/grpc to v1.58.3 ([#2275](https://github.com/keptn/lifecycle-toolkit/issues/2275)) ([66e86c0](https://github.com/keptn/lifecycle-toolkit/commit/66e86c03272d75207bd3b42014d88b1b912b9198))
* update module google.golang.org/grpc to v1.59.0 ([#2302](https://github.com/keptn/lifecycle-toolkit/issues/2302)) ([fda2315](https://github.com/keptn/lifecycle-toolkit/commit/fda231552475eaf0f60457ad42a26c4ed3473008))
* update module k8s.io/apimachinery to v0.28.3 ([#2298](https://github.com/keptn/lifecycle-toolkit/issues/2298)) ([f2f8dfe](https://github.com/keptn/lifecycle-toolkit/commit/f2f8dfec6e47517f2c476d6425c22db875f9bd3c))
* update module sigs.k8s.io/controller-runtime to v0.16.3 ([#2306](https://github.com/keptn/lifecycle-toolkit/issues/2306)) ([3d634a7](https://github.com/keptn/lifecycle-toolkit/commit/3d634a79996be6cb50805c745c51309c2f091a61))
* update opentelemetry-go monorepo (minor) ([#2108](https://github.com/keptn/lifecycle-toolkit/issues/2108)) ([4e5d29e](https://github.com/keptn/lifecycle-toolkit/commit/4e5d29e681f78590b4406ba7b74cc46ca6107e4b))
* update opentelemetry-go monorepo (minor) ([#2210](https://github.com/keptn/lifecycle-toolkit/issues/2210)) ([d577311](https://github.com/keptn/lifecycle-toolkit/commit/d5773111c327f5d30ec24437d16cf5d4454dd69e))

## [0.8.2](https://github.com/keptn/lifecycle-toolkit/compare/lifecycle-operator-v0.8.1...lifecycle-operator-v0.8.2) (2023-09-06)


### Features

* add cloud events support ([#1843](https://github.com/keptn/lifecycle-toolkit/issues/1843)) ([5b47120](https://github.com/keptn/lifecycle-toolkit/commit/5b471203e412a919903876212ac45c04f180e482))
* **lifecycle-operator:** clean up KeptnTask API by removing duplicated attributes ([#1965](https://github.com/keptn/lifecycle-toolkit/issues/1965)) ([257b220](https://github.com/keptn/lifecycle-toolkit/commit/257b220a6171ccc82d1b471002b6cf773ec9bd09))
* **metrics-operator:** add analysis controller ([#1875](https://github.com/keptn/lifecycle-toolkit/issues/1875)) ([017e08b](https://github.com/keptn/lifecycle-toolkit/commit/017e08b0a65679ca417e363f2223b7f4fef3bc55))
* **metrics-operator:** add Analysis CRD ([#1839](https://github.com/keptn/lifecycle-toolkit/issues/1839)) ([9521a16](https://github.com/keptn/lifecycle-toolkit/commit/9521a16ce4946d3169993780f2d2a4f3a75d0445))
* monorepo setup for lifecycle-operator, scheduler and runtimes ([#1857](https://github.com/keptn/lifecycle-toolkit/issues/1857)) ([84e243a](https://github.com/keptn/lifecycle-toolkit/commit/84e243a213ffba86eddd51ccc4bf4dbd61140069))


### Bug Fixes

* **lifecycle-operator:** avoid setting the overall state of an App or WorkloadInstance between state transitions ([#1871](https://github.com/keptn/lifecycle-toolkit/issues/1871)) ([ee0b085](https://github.com/keptn/lifecycle-toolkit/commit/ee0b085b05b2b9781457eba34d5d1050b3c7a604))


### Other

* **main:** release lifecycle-operator-and-scheduler libraries ([#1979](https://github.com/keptn/lifecycle-toolkit/issues/1979)) ([12d0f40](https://github.com/keptn/lifecycle-toolkit/commit/12d0f40725e466825c4a0d483fa344e5888b03ae))
* rename operator folder to lifecycle-operator ([#1819](https://github.com/keptn/lifecycle-toolkit/issues/1819)) ([97a2d25](https://github.com/keptn/lifecycle-toolkit/commit/97a2d25919c0a02165dd0dc6c7c82d57ad200139))


### Docs

* fix typos and grammar issues ([#1925](https://github.com/keptn/lifecycle-toolkit/issues/1925)) ([5570d55](https://github.com/keptn/lifecycle-toolkit/commit/5570d555bfc4bbdcbfc66b2725d5352090e5b937))
* implement KLT -&gt; Keptn name change ([#2001](https://github.com/keptn/lifecycle-toolkit/issues/2001)) ([440c308](https://github.com/keptn/lifecycle-toolkit/commit/440c3082e5400f89d791724651984ba2bc0a4724))


### Dependency Updates

* update dependency kubernetes-sigs/controller-tools to v0.13.0 ([#1930](https://github.com/keptn/lifecycle-toolkit/issues/1930)) ([8b34b63](https://github.com/keptn/lifecycle-toolkit/commit/8b34b63404d0339633ef41ff1cf2005deae8d2b7))
* update dependency kubernetes-sigs/kustomize to v5.1.1 ([#1853](https://github.com/keptn/lifecycle-toolkit/issues/1853)) ([354ab3f](https://github.com/keptn/lifecycle-toolkit/commit/354ab3f980c2569e17a0354ece417df40317d120))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to 440c308 ([#2017](https://github.com/keptn/lifecycle-toolkit/issues/2017)) ([c365734](https://github.com/keptn/lifecycle-toolkit/commit/c365734fa7e3e40b2ae4c97c61628892d040dacc))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to 88a54f9 ([#1794](https://github.com/keptn/lifecycle-toolkit/issues/1794)) ([fc976eb](https://github.com/keptn/lifecycle-toolkit/commit/fc976eb07ed9a5e49ed7d4ab1dbf187cee583e64))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to 8dbec2d ([#1995](https://github.com/keptn/lifecycle-toolkit/issues/1995)) ([2f51445](https://github.com/keptn/lifecycle-toolkit/commit/2f5144540c4b3876e800bff29c30bfded334be40))
* update github.com/keptn/lifecycle-toolkit/klt-cert-manager digest to bb133cf ([#1963](https://github.com/keptn/lifecycle-toolkit/issues/1963)) ([c7697bf](https://github.com/keptn/lifecycle-toolkit/commit/c7697bf54d5fe18b7c62c5b11801c6c83079b0a3))
* update kubernetes packages to v0.26.8 (patch) ([#1945](https://github.com/keptn/lifecycle-toolkit/issues/1945)) ([6ce03d6](https://github.com/keptn/lifecycle-toolkit/commit/6ce03d600cbb3d3d3988573c616ec7f3830ba324))
* update module github.com/onsi/ginkgo/v2 to v2.12.0 ([#2019](https://github.com/keptn/lifecycle-toolkit/issues/2019)) ([41e878f](https://github.com/keptn/lifecycle-toolkit/commit/41e878ff8bbb438efa4b221470a571687dd392e9))
* update module github.com/onsi/gomega to v1.27.10 ([#1796](https://github.com/keptn/lifecycle-toolkit/issues/1796)) ([8f14bff](https://github.com/keptn/lifecycle-toolkit/commit/8f14bffe27485a36e0b05b770a01e357402d92f7))
* update module golang.org/x/net to v0.14.0 ([#1855](https://github.com/keptn/lifecycle-toolkit/issues/1855)) ([3186188](https://github.com/keptn/lifecycle-toolkit/commit/31861889bf7b227f489b941ac4a52db86551fcc2))
* update module google.golang.org/grpc to v1.57.0 ([#1861](https://github.com/keptn/lifecycle-toolkit/issues/1861)) ([fdcbdf5](https://github.com/keptn/lifecycle-toolkit/commit/fdcbdf50365dfd69d16c679c6814e89570a8a0e2))
* update opentelemetry-go monorepo (minor) ([#1931](https://github.com/keptn/lifecycle-toolkit/issues/1931)) ([a0a1a7e](https://github.com/keptn/lifecycle-toolkit/commit/a0a1a7e97906ab56ed85da7ab9b6d1e13c902397))


### Refactoring

* **lifecycle-operator:** eventing and telemetry ([#1844](https://github.com/keptn/lifecycle-toolkit/issues/1844)) ([0130576](https://github.com/keptn/lifecycle-toolkit/commit/0130576a17a78453019c150af849c06553d799a6))
* **lifecycle-operator:** refactor event emitter unit tests ([#1867](https://github.com/keptn/lifecycle-toolkit/issues/1867)) ([2558f74](https://github.com/keptn/lifecycle-toolkit/commit/2558f742031e4d38a8006ce9894f41bddac7cd3f))

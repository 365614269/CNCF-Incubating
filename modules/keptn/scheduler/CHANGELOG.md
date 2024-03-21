# Changelog

## [0.9.2](https://github.com/keptn/lifecycle-toolkit/compare/scheduler-v0.9.1...scheduler-v0.9.2) (2024-03-19)


### Bug Fixes

* security vulnerabilities ([#3230](https://github.com/keptn/lifecycle-toolkit/issues/3230)) ([1d099d7](https://github.com/keptn/lifecycle-toolkit/commit/1d099d7a4c9b5e856de52932693b97c29bea3122))


### Other

* bump Go base images and pipelines version to 1.21 ([#3218](https://github.com/keptn/lifecycle-toolkit/issues/3218)) ([de01ca4](https://github.com/keptn/lifecycle-toolkit/commit/de01ca493b307d8c27701552549b982e22281a2e))


### Dependency Updates

* update module google.golang.org/grpc to v1.62.1 ([#3281](https://github.com/keptn/lifecycle-toolkit/issues/3281)) ([f86c49a](https://github.com/keptn/lifecycle-toolkit/commit/f86c49a8e4a72ceccab95f15d0dcde2a4e7dbfb0))

## [0.9.1](https://github.com/keptn/lifecycle-toolkit/compare/scheduler-v0.9.0...scheduler-v0.9.1) (2024-03-04)


### Other

* bump go version to 1.21 ([#3006](https://github.com/keptn/lifecycle-toolkit/issues/3006)) ([8236c25](https://github.com/keptn/lifecycle-toolkit/commit/8236c25da7ec3768e76d12eb2e8f5765a005ecfa))


### Dependency Updates

* update module github.com/stretchr/testify to v1.9.0 ([#3171](https://github.com/keptn/lifecycle-toolkit/issues/3171)) ([d334790](https://github.com/keptn/lifecycle-toolkit/commit/d3347903ad91c33ba4bf664277c53024eb02825a))
* update module golang.org/x/net to v0.21.0 ([#3091](https://github.com/keptn/lifecycle-toolkit/issues/3091)) ([44489ea](https://github.com/keptn/lifecycle-toolkit/commit/44489ea8909c5c81a2115b952bba9e3416ddd85e))
* update module google.golang.org/grpc to v1.61.1 ([#3072](https://github.com/keptn/lifecycle-toolkit/issues/3072)) ([3c9d1f3](https://github.com/keptn/lifecycle-toolkit/commit/3c9d1f3bb7dd7ebfda56563a235ff8c8ce6c61f6))
* update module google.golang.org/grpc to v1.62.0 ([#3119](https://github.com/keptn/lifecycle-toolkit/issues/3119)) ([ea061db](https://github.com/keptn/lifecycle-toolkit/commit/ea061dbb272f3fa3bf0ce99bd33617bc1dc98a18))

## [0.9.0](https://github.com/keptn/lifecycle-toolkit/compare/scheduler-v0.8.3...scheduler-v0.9.0) (2024-02-08)


### ⚠ BREAKING CHANGES

* rename KLT to Keptn ([#2554](https://github.com/keptn/lifecycle-toolkit/issues/2554))

### Features

* add annotation to select container for version extraction ([#2471](https://github.com/keptn/lifecycle-toolkit/issues/2471)) ([d093860](https://github.com/keptn/lifecycle-toolkit/commit/d093860732798b0edb58abedf567558a2c07ad21))


### Other

* add config for spell checker action, fix typos ([#2443](https://github.com/keptn/lifecycle-toolkit/issues/2443)) ([eac178f](https://github.com/keptn/lifecycle-toolkit/commit/eac178f650962208449553086d54d26d27fa4da3))
* rename KLT to Keptn ([#2554](https://github.com/keptn/lifecycle-toolkit/issues/2554)) ([15b0ac0](https://github.com/keptn/lifecycle-toolkit/commit/15b0ac0b36b8081b85b63f36e94b00065bcc8b22))
* **scheduler:** adapt namespace name ([#2742](https://github.com/keptn/lifecycle-toolkit/issues/2742)) ([c415615](https://github.com/keptn/lifecycle-toolkit/commit/c41561566a884c27d433ab589db9659a3035e703))


### Dependency Updates

* update dependency kubernetes-sigs/kustomize to v5.3.0 ([#2659](https://github.com/keptn/lifecycle-toolkit/issues/2659)) ([8877921](https://github.com/keptn/lifecycle-toolkit/commit/8877921b8be3052ce61a4f8decd96537c93df27a))
* update kubernetes packages to v0.25.16 (patch) ([#2519](https://github.com/keptn/lifecycle-toolkit/issues/2519)) ([57822a0](https://github.com/keptn/lifecycle-toolkit/commit/57822a0b6a7fc9e245f81198f077a86e71edb78d))
* update module github.com/onsi/ginkgo/v2 to v2.13.1 ([#2486](https://github.com/keptn/lifecycle-toolkit/issues/2486)) ([14dcd27](https://github.com/keptn/lifecycle-toolkit/commit/14dcd27f4b1e67803332a8dc53b42b67c7bb2030))
* update module github.com/onsi/ginkgo/v2 to v2.13.2 ([#2624](https://github.com/keptn/lifecycle-toolkit/issues/2624)) ([197c7db](https://github.com/keptn/lifecycle-toolkit/commit/197c7db78a5baf754e773ab79c5cd6a5ab9c5591))
* update module github.com/onsi/ginkgo/v2 to v2.14.0 ([#2808](https://github.com/keptn/lifecycle-toolkit/issues/2808)) ([17b0cb1](https://github.com/keptn/lifecycle-toolkit/commit/17b0cb1314778f5f1b65f4d1029ecca41bb50d3a))
* update module github.com/onsi/ginkgo/v2 to v2.15.0 ([#2855](https://github.com/keptn/lifecycle-toolkit/issues/2855)) ([1c4f410](https://github.com/keptn/lifecycle-toolkit/commit/1c4f410f5571f02254eda4c5027c8a5e3822b28e))
* update module github.com/onsi/gomega to v1.29.0 ([#2379](https://github.com/keptn/lifecycle-toolkit/issues/2379)) ([98e420a](https://github.com/keptn/lifecycle-toolkit/commit/98e420a4b2138e90e2f87c399139bd8e5a90cef5))
* update module github.com/onsi/gomega to v1.30.0 ([#2478](https://github.com/keptn/lifecycle-toolkit/issues/2478)) ([398b949](https://github.com/keptn/lifecycle-toolkit/commit/398b9493414ab5d70bd76d94b038456e58813e70))
* update module github.com/onsi/gomega to v1.31.1 ([#2856](https://github.com/keptn/lifecycle-toolkit/issues/2856)) ([d0817a7](https://github.com/keptn/lifecycle-toolkit/commit/d0817a7118e58af5326a43f1a059f2eddfa36215))
* update module golang.org/x/net to v0.18.0 ([#2479](https://github.com/keptn/lifecycle-toolkit/issues/2479)) ([6ddd8ee](https://github.com/keptn/lifecycle-toolkit/commit/6ddd8eeec5eabb0c67b5a7b9965a34368f62c8d5))
* update module golang.org/x/net to v0.19.0 ([#2619](https://github.com/keptn/lifecycle-toolkit/issues/2619)) ([af2d0a5](https://github.com/keptn/lifecycle-toolkit/commit/af2d0a509b670792e06e2d05ab4be261d3bb54f4))
* update module golang.org/x/net to v0.20.0 ([#2786](https://github.com/keptn/lifecycle-toolkit/issues/2786)) ([8294c7b](https://github.com/keptn/lifecycle-toolkit/commit/8294c7b471d7f4d33961513e056c36ba14c940c7))
* update module google.golang.org/grpc to v1.60.0 ([#2681](https://github.com/keptn/lifecycle-toolkit/issues/2681)) ([7dd45a3](https://github.com/keptn/lifecycle-toolkit/commit/7dd45a33fba8fd3235e40202ece9057cef429bb6))
* update module google.golang.org/grpc to v1.60.1 ([#2724](https://github.com/keptn/lifecycle-toolkit/issues/2724)) ([31d69dd](https://github.com/keptn/lifecycle-toolkit/commit/31d69dd33df76f0a5f9b2d46af822e5f43e681a5))
* update module google.golang.org/grpc to v1.61.0 ([#2888](https://github.com/keptn/lifecycle-toolkit/issues/2888)) ([7a56cbd](https://github.com/keptn/lifecycle-toolkit/commit/7a56cbd1f528bb73c1070611d6b28005c875fe36))
* update module k8s.io/klog/v2 to v2.110.1 ([#2409](https://github.com/keptn/lifecycle-toolkit/issues/2409)) ([d2c3e14](https://github.com/keptn/lifecycle-toolkit/commit/d2c3e148cd1181e50f679ca859a016f762eaca84))
* update module k8s.io/klog/v2 to v2.120.0 ([#2794](https://github.com/keptn/lifecycle-toolkit/issues/2794)) ([e2c2cff](https://github.com/keptn/lifecycle-toolkit/commit/e2c2cffa18c9787a4b3f05b0982d8442d4621f59))
* update module k8s.io/klog/v2 to v2.120.1 ([#2854](https://github.com/keptn/lifecycle-toolkit/issues/2854)) ([5982d73](https://github.com/keptn/lifecycle-toolkit/commit/5982d73e693e55cba07892c6870d3906a16b78b6))
* update module sigs.k8s.io/controller-runtime to v0.13.2 ([#2378](https://github.com/keptn/lifecycle-toolkit/issues/2378)) ([59a9a4c](https://github.com/keptn/lifecycle-toolkit/commit/59a9a4c4ddb51b94fda0db4dc216df480b0c59a8))

## [0.8.3](https://github.com/keptn/lifecycle-toolkit/compare/scheduler-v0.8.2...scheduler-v0.8.3) (2023-10-30)


### Features

* adapt code to use KeptnWorkloadVersion instead of KeptnWorkloadInstance ([#2255](https://github.com/keptn/lifecycle-toolkit/issues/2255)) ([c06fae1](https://github.com/keptn/lifecycle-toolkit/commit/c06fae13daa2aa98a3daf71abafe0e8ce4e5f4a3))
* add test and lint cmd to makefiles ([#2176](https://github.com/keptn/lifecycle-toolkit/issues/2176)) ([c55e0a9](https://github.com/keptn/lifecycle-toolkit/commit/c55e0a9f368c82ad3032eb676edd59e68b29fad6))


### Other

* adapt Makefile command to run unit tests ([#2072](https://github.com/keptn/lifecycle-toolkit/issues/2072)) ([2db2569](https://github.com/keptn/lifecycle-toolkit/commit/2db25691748beedbb02ed92806d327067c422285))
* **scheduler:** improve logging ([#2283](https://github.com/keptn/lifecycle-toolkit/issues/2283)) ([59fa565](https://github.com/keptn/lifecycle-toolkit/commit/59fa56584003bd1d97ecf8d2f9246b1789a3cde4))


### Dependency Updates

* update dependency kubernetes-sigs/kustomize to v5.2.1 ([#2308](https://github.com/keptn/lifecycle-toolkit/issues/2308)) ([6653a47](https://github.com/keptn/lifecycle-toolkit/commit/6653a47d4156c0e60aa471f11a643a2664669023))
* update kubernetes packages (patch) ([#2102](https://github.com/keptn/lifecycle-toolkit/issues/2102)) ([b2853f9](https://github.com/keptn/lifecycle-toolkit/commit/b2853f9ecdfb4b7b81d0b88cf782b82c9958c5cb))
* update module github.com/onsi/ginkgo/v2 to v2.12.1 ([#2156](https://github.com/keptn/lifecycle-toolkit/issues/2156)) ([dbf2867](https://github.com/keptn/lifecycle-toolkit/commit/dbf2867133067b162e82b71b6547c3dfac95d0af))
* update module github.com/onsi/ginkgo/v2 to v2.13.0 ([#2272](https://github.com/keptn/lifecycle-toolkit/issues/2272)) ([0df464d](https://github.com/keptn/lifecycle-toolkit/commit/0df464dd8e4fc7729deeb5bae4938b236902d661))
* update module github.com/onsi/gomega to v1.28.0 ([#2209](https://github.com/keptn/lifecycle-toolkit/issues/2209)) ([c0726d0](https://github.com/keptn/lifecycle-toolkit/commit/c0726d0b0e9d9732123aaf8b1ad012bc24672b84))
* update module github.com/onsi/gomega to v1.28.1 ([#2343](https://github.com/keptn/lifecycle-toolkit/issues/2343)) ([64b1508](https://github.com/keptn/lifecycle-toolkit/commit/64b1508f0e383aa7fbc406e17e2cc66546601e53))
* update module golang.org/x/net to v0.15.0 ([#2065](https://github.com/keptn/lifecycle-toolkit/issues/2065)) ([50ce9c0](https://github.com/keptn/lifecycle-toolkit/commit/50ce9c09914f505ffaf33eee41564afa65661215))
* update module golang.org/x/net to v0.16.0 ([#2249](https://github.com/keptn/lifecycle-toolkit/issues/2249)) ([e89ea71](https://github.com/keptn/lifecycle-toolkit/commit/e89ea71bc1a2d69828179c64ffe3c34ce359dd94))
* update module golang.org/x/net to v0.17.0 ([#2267](https://github.com/keptn/lifecycle-toolkit/issues/2267)) ([8443874](https://github.com/keptn/lifecycle-toolkit/commit/8443874254cda9e5f4c662cab1a3e5e3b3277435))
* update module google.golang.org/grpc to v1.58.0 ([#2066](https://github.com/keptn/lifecycle-toolkit/issues/2066)) ([6fae5a7](https://github.com/keptn/lifecycle-toolkit/commit/6fae5a7ebf356625b4754b7890f7c71dbb4ac0a6))
* update module google.golang.org/grpc to v1.58.1 ([#2115](https://github.com/keptn/lifecycle-toolkit/issues/2115)) ([d08df40](https://github.com/keptn/lifecycle-toolkit/commit/d08df40188bc633037c49a1468a70eefc960a4a1))
* update module google.golang.org/grpc to v1.58.2 ([#2163](https://github.com/keptn/lifecycle-toolkit/issues/2163)) ([5efa650](https://github.com/keptn/lifecycle-toolkit/commit/5efa6502403daa37bdfc51fa8600da6b1f845ac2))
* update module google.golang.org/grpc to v1.58.3 ([#2275](https://github.com/keptn/lifecycle-toolkit/issues/2275)) ([66e86c0](https://github.com/keptn/lifecycle-toolkit/commit/66e86c03272d75207bd3b42014d88b1b912b9198))
* update module google.golang.org/grpc to v1.59.0 ([#2302](https://github.com/keptn/lifecycle-toolkit/issues/2302)) ([fda2315](https://github.com/keptn/lifecycle-toolkit/commit/fda231552475eaf0f60457ad42a26c4ed3473008))
* update module k8s.io/kubernetes to v1.25.15 ([#2305](https://github.com/keptn/lifecycle-toolkit/issues/2305)) ([7c554be](https://github.com/keptn/lifecycle-toolkit/commit/7c554bee758179e8a6a602fc338801e00f56b5dc))

## [0.8.2](https://github.com/keptn/lifecycle-toolkit/compare/scheduler-v0.8.1...scheduler-v0.8.2) (2023-09-06)


### Other

* fix minor security issues ([#1728](https://github.com/keptn/lifecycle-toolkit/issues/1728)) ([ea73cd9](https://github.com/keptn/lifecycle-toolkit/commit/ea73cd983102632fb162e1b4c8ae56687b288b25))
* **main:** release lifecycle-operator-and-scheduler libraries ([#1979](https://github.com/keptn/lifecycle-toolkit/issues/1979)) ([12d0f40](https://github.com/keptn/lifecycle-toolkit/commit/12d0f40725e466825c4a0d483fa344e5888b03ae))
* release scheduler 0.8.2 ([#2032](https://github.com/keptn/lifecycle-toolkit/issues/2032)) ([cb4d2b1](https://github.com/keptn/lifecycle-toolkit/commit/cb4d2b14a7a772572b505fa844db6f08a45db291))


### Docs

* implement KLT -&gt; Keptn name change ([#2001](https://github.com/keptn/lifecycle-toolkit/issues/2001)) ([440c308](https://github.com/keptn/lifecycle-toolkit/commit/440c3082e5400f89d791724651984ba2bc0a4724))
* keptn Scheduler architecture documentation ([#1777](https://github.com/keptn/lifecycle-toolkit/issues/1777)) ([ce96200](https://github.com/keptn/lifecycle-toolkit/commit/ce96200b9bfed62062b199845104c4493b3a2627))


### Dependency Updates

* update dependency kubernetes-sigs/kustomize to v5.1.1 ([#1853](https://github.com/keptn/lifecycle-toolkit/issues/1853)) ([354ab3f](https://github.com/keptn/lifecycle-toolkit/commit/354ab3f980c2569e17a0354ece417df40317d120))
* update kubernetes packages (patch) ([#1786](https://github.com/keptn/lifecycle-toolkit/issues/1786)) ([cba2de5](https://github.com/keptn/lifecycle-toolkit/commit/cba2de5a5cd04c094131552aaf92c2b85ac23d21))
* update module github.com/onsi/ginkgo/v2 to v2.12.0 ([#2019](https://github.com/keptn/lifecycle-toolkit/issues/2019)) ([41e878f](https://github.com/keptn/lifecycle-toolkit/commit/41e878ff8bbb438efa4b221470a571687dd392e9))
* update module github.com/onsi/gomega to v1.27.10 ([#1796](https://github.com/keptn/lifecycle-toolkit/issues/1796)) ([8f14bff](https://github.com/keptn/lifecycle-toolkit/commit/8f14bffe27485a36e0b05b770a01e357402d92f7))
* update module github.com/onsi/gomega to v1.27.9 ([#1787](https://github.com/keptn/lifecycle-toolkit/issues/1787)) ([90b6ce9](https://github.com/keptn/lifecycle-toolkit/commit/90b6ce92253f52a43f3c13dddaa918ca73b515d0))
* update module golang.org/x/net to v0.12.0 ([#1662](https://github.com/keptn/lifecycle-toolkit/issues/1662)) ([49318bf](https://github.com/keptn/lifecycle-toolkit/commit/49318bfc40497a120304de9d831dfe033259220f))
* update module golang.org/x/net to v0.14.0 ([#1855](https://github.com/keptn/lifecycle-toolkit/issues/1855)) ([3186188](https://github.com/keptn/lifecycle-toolkit/commit/31861889bf7b227f489b941ac4a52db86551fcc2))
* update module google.golang.org/grpc to v1.56.2 ([#1663](https://github.com/keptn/lifecycle-toolkit/issues/1663)) ([0b618c4](https://github.com/keptn/lifecycle-toolkit/commit/0b618c4bf15209fbb81ec7c05f1d05543bdfd1cf))
* update module google.golang.org/grpc to v1.57.0 ([#1861](https://github.com/keptn/lifecycle-toolkit/issues/1861)) ([fdcbdf5](https://github.com/keptn/lifecycle-toolkit/commit/fdcbdf50365dfd69d16c679c6814e89570a8a0e2))
* update module k8s.io/kubernetes to v1.25.13 ([#1958](https://github.com/keptn/lifecycle-toolkit/issues/1958)) ([fb23f09](https://github.com/keptn/lifecycle-toolkit/commit/fb23f0948aa0395636b1290f3c7b3b28cbf54976))

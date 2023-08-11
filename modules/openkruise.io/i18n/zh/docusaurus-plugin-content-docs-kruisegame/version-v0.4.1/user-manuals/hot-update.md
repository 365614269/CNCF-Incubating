# 游戏服热更新

游戏服更新是游戏服应用交付中尤为重要的一环。作为有状态类型业务，游戏服的更新往往对云原生基础设施有着更高的要求。本文主要介绍如何利用OKG的原地升级能力实现游戏服热更新。

## 游戏服与容器

在介绍热更方法之前，或许我们需要先明确游戏服与容器的关系。在OKG的概念里，一个游戏服(GameServer)中可以包含多个容器，每个容器功能作用不尽相同，各自对应不同的容器镜像。当然，一个游戏服也可以只包含一个容器。游戏服包含一个容器、还是包含多个容器对应着两种不同的架构思想。

单容器的游戏服，更贴近虚拟机的运维管理方式。无论是状态的管理、或者小版本的热更都不借助Kubernetes的能力，沿用过去的运维方式进行。比如，游戏服的单容器中存在多个进程，多个脚本文件或配置文件，游戏服引擎常驻进程通常会通过构建新的容器进行实现新版发布，而新的脚本、资源、或配置的更新往往依赖对象存储的挂载、或是自研程序的动态拉取。并且更新的情况由业务自行判断，整个过程以非云原生的方式进行。在业内，我们称这种游戏服为富容器。富容器热更新的问题在于：

- 无法对脚本/资源/配置文件进行云原生化的版本管理。由于容器镜像并没有发生变化，运维人员对当前容器中运行的脚本文件等版本不得而知。游戏上线后小版本的迭代十分频繁，当故障出现时，没有版本管理的系统将难以定位问题，这很大程度上提高了运维复杂度。
- 更新状态难以定位。即使对容器中的文件进行了更新替换，但执行重载命令时难以确定当前热更文件是否已经挂载完毕，这种更新成功与否的状态维护需要交给运维者额外管理，也一定程度上提高了运维复杂度。
- 无法灰度升级。在更新时，为了控制影响面，往往需要先更新低重要性的游戏服，确认无误后再灰度其余游戏服。但无论是对象存储挂载的方式还是程序拉取的方式很难做到灰度发布。一旦全量发布出现问题，故障影响面是非常大的。
- 在容器异常时，pod重建拉起旧版本的镜像，热更文件并未能持续化保留。

针对游戏服热更场景，更理想的做法是使用多容器的游戏服架构，将热更的部分作为sidecar容器与main容器一同部署在同一个游戏服(GameServer)中，二者通过emptyDir共享热更文件。更新时只需更新sidecar容器即可。这样一来，游戏服的热更将以云原生的方式进行：

- sidecar容器镜像具有版本属性，解决了版本管理问题。
- Kubernetes容器更新成功后处于Ready状态，能够感知sidecar更新是否成功。
- OKG提供多种更新策略，可按照发布需求自行控制发布对象，完成灰度发布。
- 即使容器异常发生重启，热更文件随着镜像的固化而持续化保留了下来。

## 基于原地升级的游戏服热更新

### 原地升级

在标准的Kubernetes中，应用的更新是通过更改资源对象中Image字段实现的。但原生的workload，如Deployment或StatefulSet管理的pod在更新了Image之后会出现重建的情况，pod的生命周期与容器的生命周期耦合在一起，上文提到的多容器架构的游戏服热更新在原生Kubernetes的workload下变成了无稽之谈。

OKG的GameServerSet提供了一种原地升级的能力，在保证整个游戏服生命周期不变的情况下定向更新其中某一个容器，不会导致游戏服重新创建。sidecar容器更新过程游戏服正常运行，玩家不会收到任何影响。

如下图所示，蓝色部分为热更部分，橘色部分为非热更部分。我们将Game Script容器从版本V1更新至版本V2后，整个pod不会重建，橘色部分不受到任何影响，Game Engine正常平稳运行


![hot-update.png](/img/kruisegame/user-manuals/hot-update.png)

### 使用示例

本文使用2048网页版作为示例。在示例中，我们将看到如何在不影响游戏服生命周期的前提条件下更新游戏脚本。

部署带有sidecar容器的游戏服，使用GameServerSet作为游戏服负载，设置：
- pod更新策略选择原地升级
- 使用AlibabaCloud-SLB网络模型暴露服务
- 两个容器，其中app-2048为主容器，承载主要游戏逻辑；sidecar为伴生容器，存放热更文件。二者通过emptyDir共享文件目录
    - sidecar启动时将存放热更文件的目录下文件（/app/js）同步至共享目录下（/app/scripts），同步后sleep不退出
    - app-2048容器使用/var/www/html/js目录下的游戏脚本

```bash
cat <<EOF | kubectl apply -f -
apiVersion: game.kruise.io/v1alpha1
kind: GameServerSet
metadata:
  name: gss-2048
  namespace: default
spec:
  replicas: 1
  updateStrategy:
    rollingUpdate:
      podUpdatePolicy: InPlaceIfPossible
  network:
    networkType: AlibabaCloud-SLB
    networkConf:
      - name: SlbIds
        value: lb-bp1oqahx3jnr7j3f6vyp8
      - name: PortProtocols
        value: 80/TCP
  gameServerTemplate:
    spec:
      containers:
        - image: registry.cn-beijing.aliyuncs.com/acs/2048:v1.0
          name: app-2048
          volumeMounts:
            - name: shared-dir
              mountPath: /var/www/html/js
        - image: registry.cn-beijing.aliyuncs.com/acs/2048-sidecar:v1.0
          name: sidecar
          args:
            - bash
            - -c
            - rsync -aP /app/js/* /app/scripts/ && while true; do echo 11;sleep 2; done
          volumeMounts:
            - name: shared-dir
              mountPath: /app/scripts
      volumes:
        - name: shared-dir
          emptyDir: {}
EOF
```

生成1个GameServer以及对应的1个Pod：

```bash
kubectl get gs
NAME          STATE   OPSSTATE   DP    UP   AGE
gss-2048-0    Ready   None       0     0    13s

kubectl get pod
NAME          READY   STATUS    RESTARTS   AGE
gss-2048-0    2/2     Running   0          13s
```

此时访问游戏网页（游戏服网络相关内容可参考网络模型文档），游戏结束时显示`Game over!`字样：

<img src={require('/static/img/kruisegame/user-manuals/2048-v1.png').default} style={{ height: '600px' , width: '400px'}} />

接下来，我们希望更新游戏服脚本，将游戏结束时的显示字样变为 `*_* Game over!`

修改对应脚本文件html_actuator.js，并构建新的sidecar镜像，将镜像tag命名为v2.0。（在实际生产中，这一过程可通过CI流程完成）

镜像更新后只需更新GameServerSet对应的容器镜像版本即可：

```bash
kubectl edit gss gss-2048
...
      - image: registry.cn-beijing.aliyuncs.com/acs/2048-sidecar:v2.0
        name: sidecar
...
```

一段时间过后，发现gs已从Updating变为Ready，Pod已经更新完毕，restarts次数变为1，但Age并没有减少。

```bash
kubectl get pod
NAME             READY   STATUS    RESTARTS      AGE
gss-2048-0       2/2     Running   1 (33s ago)   8m55s
```

此时对app-2048容器执行重载命令

```bash
kubectl exec gss-2048-0 -c app-2048 -- /usr/sbin/nginx -s reload
```

打开无痕浏览器，进行游戏，游戏结束时提示字样已更新：

<img src={require('/static/img/kruisegame/user-manuals/2048-v2.png').default} style={{ height: '600px' , width: '400px'}} />

### 文件热更后的重载方式

在上面的示例中，对单个pod使用exec执行命令的方式重载。
而在批量管理时，重载操作太过繁琐复杂。下面提供了几种文件热更后的重载方式，以供参考。

#### 手动批量重载

当全部游戏服更新Ready后，可借助批量管理工具kubectl-pexec批量在容器中执行exec重载命令。完成游戏服热重载。

#### 通过inotify跟踪热更文件目录

inotify是Linux文件监控系统框架。通过inotify，主游戏服业务容器可以监听热更文件目录下文件的变化，进而触发更新。

使用inotify需要在容器中安装inotify-tools:

```bash
apt-get install inotify-tools
```

以上述2048游戏为例，在原镜像基础之上，app-2048容器监听 /var/www/html/js/ 目录，当发现文件变化时自动执行重载命令。脚本如下所示，在容器启动时执行即可。值得注意的是重载命令应为幂等的。

```shell
inotifywait -mrq --timefmt '%d/%m/%y %H:%M' --format '%T %w%f%e' -e modify,delete,create,attrib /var/www/html/js/ |  while read file
do
	/usr/sbin/nginx -s reload
	echo "reload successfully"
done
```

将上述程序固化至镜像中，构建出新的镜像`registry.cn-beijing.aliyuncs.com/acs/2048:v1.0-inotify`，再次实验（其他字段不变），将sidecar镜像从v1.0替换到v2.0后，会发现已经不需要手动输入重载命令已完成全部热更过程。
完整的yaml如下
```yaml
kind: GameServerSet
metadata:
  name: gss-2048
  namespace: default
spec:
  replicas: 1
  updateStrategy:
    rollingUpdate:
      podUpdatePolicy: InPlaceIfPossible
  network:
    networkType: AlibabaCloud-SLB
    networkConf:
      - name: SlbIds
        value: lb-bp1oqahx3jnr7j3f6vyp8
      - name: PortProtocols
        value: 80/TCP
  gameServerTemplate:
    spec:
      containers:
        - image: registry.cn-beijing.aliyuncs.com/acs/2048:v1.0-inotify
          name: app-2048
          volumeMounts:
            - name: shared-dir
              mountPath: /var/www/html/js
        - image: registry.cn-beijing.aliyuncs.com/acs/2048-sidecar:v1.0 #热更时替换成v2.0
          name: sidecar
          args:
            - bash
            - -c
            - rsync -aP /app/js/* /app/scripts/ && while true; do echo 11;sleep 2; done
          volumeMounts:
            - name: shared-dir
              mountPath: /app/scripts
      volumes:
        - name: shared-dir
          emptyDir: {}
```

#### sidecar触发http请求

主游戏服业务容器暴露一个http接口，sidecar在启动成功后向本地127.0.0.1发送重载请求，由于pod下容器共享网络命名空间，主容器接收到请求后进行文件重载。

以上述2048游戏为例，在原镜像基础之上：

- app-2048容器新增reload接口，以下是js代码示例

  ```js
  var http = require('http');
  var exec = require('child_process').exec;

  var server = http.createServer(function(req, res) {
    if (req.url === '/reload') {
      exec('/usr/sbin/nginx -s reload', function(error, stdout, stderr) {
        if (error) {
          console.error('exec error: ' + error);
          res.statusCode = 500;
          res.end('Error: ' + error.message);
          return;
        }
        console.log('stdout: ' + stdout);
        console.error('stderr: ' + stderr);
        res.statusCode = 200;
        res.end();
      });
    } else {
      res.statusCode = 404;
      res.end('Not found');
    }
  });

  server.listen(3000, function() {
    console.log('Server is running on port 3000');
  });
  ```
- 同时，sidecar容器新增请求脚本request.sh，容器启动后利用postStart增加发送请求命令，如下所示

  ```yaml
  ...
            name: sidecar
            lifecycle:
              postStart:
                exec:
                  command:
                    - bash
                    - -c
                    - ./request.sh
  ...
  ```

  对应request.sh脚本如下所示，具有重试机制，确认重载成功再退出

  ```shell
  #!/bin/bash

  # 循环发送 HTTP 请求，直到服务器返回成功响应为止
  while true; do
    response=$(curl -s -w "%{http_code}" http://localhost:3000/reload)
    if [[ $response -eq 200 ]]; then
      echo "Server reloaded successfully!"
      break
    else
      echo "Server reload failed, response code: $response"
    fi
    sleep 1
  done
  ```

这样一来，在文件更新后也可完成自动重载。

将上述程序固化至镜像中，构建出以下新的镜像：
- `registry.cn-beijing.aliyuncs.com/acs/2048:v1.0-http`
- `registry.cn-beijing.aliyuncs.com/acs/2048-sidecar:v1.0-http`
- `registry.cn-beijing.aliyuncs.com/acs/2048-sidecar:v2.0-http`

替换新镜像再次实验（注意yaml中sidecar需要增加lifecycle字段）。将sidecar镜像从v1.0-http替换到v2.0-http后，会发现已经不需要手动输入重载命令已完成全部热更过程。
完整的yaml如下:
```yaml
kind: GameServerSet
metadata:
  name: gss-2048
  namespace: default
spec:
  replicas: 1
  updateStrategy:
    rollingUpdate:
      podUpdatePolicy: InPlaceIfPossible
  network:
    networkType: AlibabaCloud-SLB
    networkConf:
      - name: SlbIds
        value: lb-bp1oqahx3jnr7j3f6vyp8
      - name: PortProtocols
        value: 80/TCP
  gameServerTemplate:
    spec:
      containers:
        - image: registry.cn-beijing.aliyuncs.com/acs/2048:v1.0-http
          name: app-2048
          volumeMounts:
            - name: shared-dir
              mountPath: /var/www/html/js
        - image: registry.cn-beijing.aliyuncs.com/acs/2048-sidecar:v1.0-http #热更时替换成v2.0-http
          name: sidecar
          lifecycle:
            postStart:
              exec:
                command:
                  - bash
                  - -c
                  - ./request.sh
          args:
            - bash
            - -c
            - rsync -aP /app/js/* /app/scripts/ && while true; do echo 11;sleep 2; done
          volumeMounts:
            - name: shared-dir
              mountPath: /app/scripts
      volumes:
        - name: shared-dir
          emptyDir: {}
```

#### 全托管的热更重载

OKG具备触发容器中执行命令的能力，基于该功能OKG可提供全自动化的热更新能力，让用户不再过度关心热更重载问题。如若您有这方面需求，可以在GitHub提交issue，和社区开发者一起讨论OKG热更功能演进路线。

### 停服原地热更

游戏场景下狭义上的热更是指不影响玩家正常游戏的不停服更新。然而在有些场景下，游戏服停服更新也需要依赖原地升级能力。

#### 网络元数据不变

游戏服的有状态特性时常体现在网络信息上。由于每个游戏服都是独特的，无法使用k8s svc负载均衡的概念，往往游戏开发者会基于IP实现路由分发机制，这时我们需要在游戏更新时避免游戏服IP信息变化。OKG的原地升级能力能够满足上述需求。

#### 共享内存不丢失

游戏服创建后调度到某宿主机上，游戏业务利用共享内存降低数据落盘延迟，这样一来，相当于游戏服在本地增加了一层缓存。在游戏服更新时，即时出现短暂的服务暂停时间，但由于缓存的存在，游戏服的终止以及启动速度较快，停服时间也会大大减少。共享内存的实现也依赖于OKG的原地升级能力，保证对应缓存数据不会丢失。
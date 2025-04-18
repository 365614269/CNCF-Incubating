---
type: docs
title: "How-to: Persist Scheduler Jobs"
linkTitle: "How-to: Persist Scheduler Jobs"
weight: 50000
description: "Configure Scheduler to persist its database to make it resilient to restarts"
---

The [Scheduler]({{< ref scheduler.md >}}) service is responsible for writing jobs to its embedded Etcd database and scheduling them for execution.
By default, the Scheduler service database writes data to a Persistent Volume Claim volume of size `1Gb`, using the cluster's default [storage class](https://kubernetes.io/docs/concepts/storage/storage-classes/).
This means that there is no additional parameter required to run the scheduler service reliably on most Kubernetes deployments, although you will need [additional configuration](#storage-class) if a default StorageClass is not available or when running a production environment.

{{% alert title="Warning" color="warning" %}}
The default storage size for the Scheduler is `1Gi`, which is likely not sufficient for most production deployments.
Remember that the Scheduler is used for [Actor Reminders]({{< ref actors-timers-reminders.md >}}) & [Workflows]({{< ref workflow-overview.md >}}), and the [Jobs API]({{< ref jobs_api.md >}}).
You may want to consider reinstalling Dapr with a larger Scheduler storage of at least `16Gi` or more.
For more information, see the [ETCD Storage Disk Size](#etcd-storage-disk-size) section below.
{{% /alert %}}

## Production Setup

### ETCD Storage Disk Size

The default storage size for the Scheduler is `1Gb`.
This size is likely not sufficient for most production deployments.
When the storage size is exceeded, the Scheduler will log an error similar to the following:

```
error running scheduler: etcdserver: mvcc: database space exceeded
```

Knowing the safe upper bound for your storage size is not an exact science, and relies heavily on the number, persistence, and the data payload size of your application jobs.
The [Job API]({{< ref jobs_api.md >}}) and [Actor Reminders]({{< ref actors-timers-reminders.md >}}) transparently maps one to one to the usage of your applications.
Workflows create a large number of jobs as Actor Reminders, however these jobs are short lived- matching the lifecycle of each workflow execution.
The data payload of jobs created by Workflows is typically empty or small.

The Scheduler uses Etcd as its storage backend database.
By design, Etcd persists historical transactions and data in form of [Write-Ahead Logs (WAL) and snapshots](https://etcd.io/docs/v3.5/learning/persistent-storage-files/).
This means the actual disk usage of Scheduler will be higher than the current observable database state, often by a number of multiples.

### Setting the Storage Size on Installation

If you need to increase an **existing** Scheduler storage size, see the [Increase Scheduler Storage Size](#increase-existing-scheduler-storage-size) section below.
To increase the storage size (in this example- `16Gi`) for a **fresh** Dapr installation, you can use the following command:

{{< tabs "Dapr CLI" "Helm" >}}
 <!-- Dapr CLI -->
{{% codetab %}}

```bash
dapr init -k --set dapr_scheduler.cluster.storageSize=16Gi --set dapr_scheduler.etcdSpaceQuota=16Gi
```

{{% /codetab %}}

 <!-- Helm -->
{{% codetab %}}

```bash
helm upgrade --install dapr dapr/dapr \
--version={{% dapr-latest-version short="true" %}} \
--namespace dapr-system \
--create-namespace \
--set dapr_scheduler.cluster.storageSize=16Gi \
--set dapr_scheduler.etcdSpaceQuota=16Gi \
--wait
```

{{% /codetab %}}
{{< /tabs >}}

{{% alert title="Note" color="primary" %}}
For storage providers that do NOT support dynamic volume expansion: If Dapr has ever been installed on the cluster before, the Scheduler's Persistent Volume Claims must be manually uninstalled in order for new ones with increased storage size to be created.
```bash
kubectl delete pvc -n dapr-system dapr-scheduler-data-dir-dapr-scheduler-server-0 dapr-scheduler-data-dir-dapr-scheduler-server-1 dapr-scheduler-data-dir-dapr-scheduler-server-2
```
Persistent Volume Claims are not deleted automatically with an [uninstall]({{< ref dapr-uninstall.md >}}). This is a deliberate safety measure to prevent accidental data loss.
{{% /alert %}}

#### Increase existing Scheduler Storage Size

{{% alert title="Warning" color="warning" %}}
Not all storage providers support dynamic volume expansion.
Please see your storage provider documentation to determine if this feature is supported, and what to do if it is not.
{{% /alert %}}

By default, each Scheduler will create a Persistent Volume and Persistent Volume Claim of size `1Gi` against the [default `standard` storage class](#storage-class) for each Scheduler replica.
These will look similar to the following, where in this example we are running Scheduler in HA mode.

```
NAMESPACE     NAME                                              STATUS   VOLUME                                     CAPACITY   ACCESS MODES   STORAGECLASS   VOLUMEATTRIBUTESCLASS   AGE
dapr-system   dapr-scheduler-data-dir-dapr-scheduler-server-0   Bound    pvc-9f699d2e-f347-43b0-aa98-57dcf38229c5   1Gi        RWO            standard       <unset>                 3m25s
dapr-system   dapr-scheduler-data-dir-dapr-scheduler-server-1   Bound    pvc-f4c8be7b-ffbe-407b-954e-7688f2482caa   1Gi        RWO            standard       <unset>                 3m25s
dapr-system   dapr-scheduler-data-dir-dapr-scheduler-server-2   Bound    pvc-eaad5fb1-98e9-42a5-bcc8-d45dba1c4b9f   1Gi        RWO            standard       <unset>                 3m25s
```

```
NAME                                       CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS   CLAIM                                                         STORAGECLASS   VOLUMEATTRIBUTESCLASS   REASON   AGE
pvc-9f699d2e-f347-43b0-aa98-57dcf38229c5   1Gi        RWO            Delete           Bound    dapr-system/dapr-scheduler-data-dir-dapr-scheduler-server-0   standard       <unset>                          4m24s
pvc-eaad5fb1-98e9-42a5-bcc8-d45dba1c4b9f   1Gi        RWO            Delete           Bound    dapr-system/dapr-scheduler-data-dir-dapr-scheduler-server-2   standard       <unset>                          4m24s
pvc-f4c8be7b-ffbe-407b-954e-7688f2482caa   1Gi        RWO            Delete           Bound    dapr-system/dapr-scheduler-data-dir-dapr-scheduler-server-1   standard       <unset>                          4m24s
```

To expand the storage size of the Scheduler, follow these steps:

1. First, ensure that the storage class supports volume expansion, and that the `allowVolumeExpansion` field is set to `true` if it is not already.

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: standard
provisioner: my.driver
allowVolumeExpansion: true
...
```

2. Delete the Scheduler StatefulSet whilst preserving the Bound Persistent Volume Claims.

```bash
kubectl delete sts -n dapr-system dapr-scheduler-server --cascade=orphan
```

3. Increase the size of the Persistent Volume Claims to the desired size by editing the `spec.resources.requests.storage` field.
 Again in this case, we are assuming that the Scheduler is running in HA mode with 3 replicas.

```bash
kubectl edit pvc -n dapr-system dapr-scheduler-data-dir-dapr-scheduler-server-0 dapr-scheduler-data-dir-dapr-scheduler-server-1 dapr-scheduler-data-dir-dapr-scheduler-server-2
```

4. Recreate the Scheduler StatefulSet by [installing Dapr with the desired storage size](#setting-the-storage-size-on-installation).

### Storage Class

In case your Kubernetes deployment does not have a default storage class or you are configuring a production cluster, defining a storage class is required.

A persistent volume is backed by a real disk that is provided by the hosted Cloud Provider or Kubernetes infrastructure platform.
Disk size is determined by how many jobs are expected to be persisted at once; however, 64Gb should be more than sufficient for most production scenarios.
Some Kubernetes providers recommend using a [CSI driver](https://kubernetes.io/docs/concepts/storage/volumes/#csi) to provision the underlying disks.
Below are a list of useful links to the relevant documentation for creating a persistent disk for the major cloud providers:
- [Google Cloud Persistent Disk](https://cloud.google.com/compute/docs/disks)
- [Amazon EBS Volumes](https://aws.amazon.com/blogs/storage/persistent-storage-for-kubernetes/)
- [Azure AKS Storage Options](https://learn.microsoft.com/azure/aks/concepts-storage)
- [Digital Ocean Block Storage](https://www.digitalocean.com/docs/kubernetes/how-to/add-volumes/)
- [VMWare vSphere Storage](https://docs.vmware.com/VMware-vSphere/7.0/vmware-vsphere-with-tanzu/GUID-A19F6480-40DC-4343-A5A9-A5D3BFC0742E.html)
- [OpenShift Persistent Storage](https://docs.openshift.com/container-platform/4.6/storage/persistent_storage/persistent-storage-aws-efs.html)
- [Alibaba Cloud Disk Storage](https://www.alibabacloud.com/help/ack/ack-managed-and-ack-dedicated/user-guide/create-a-pvc)


Once the storage class is available, you can install Dapr using the following command, with Scheduler configured to use the storage class (replace `my-storage-class` with the name of the storage class):

{{% alert title="Note" color="primary" %}}
If Dapr is already installed, the control plane needs to be completely [uninstalled]({{< ref dapr-uninstall.md >}}) in order for the Scheduler `StatefulSet` to be recreated with the new persistent volume.
{{% /alert %}}

{{< tabs "Dapr CLI" "Helm" >}}
 <!-- Dapr CLI -->
{{% codetab %}}

```bash
dapr init -k --set dapr_scheduler.cluster.storageClassName=my-storage-class
```

{{% /codetab %}}

 <!-- Helm -->
{{% codetab %}}

```bash
helm upgrade --install dapr dapr/dapr \
--version={{% dapr-latest-version short="true" %}} \
--namespace dapr-system \
--create-namespace \
--set dapr_scheduler.cluster.storageClassName=my-storage-class \
--wait
```

{{% /codetab %}}
{{< /tabs >}}

## Ephemeral Storage

When running in non-HA mode, the Scheduler can be optionally made to use ephemeral storage, which is in-memory storage that is **not** resilient to restarts. For example, all jobs data is lost after a Scheduler restart.
This is useful in non-production deployments or for testing where storage is not available or required.

{{% alert title="Note" color="primary" %}}
If Dapr is already installed, the control plane needs to be completely [uninstalled]({{< ref dapr-uninstall.md >}}) in order for the Scheduler `StatefulSet` to be recreated without the persistent volume.
{{% /alert %}}

{{< tabs "Dapr CLI" "Helm" >}}
 <!-- Dapr CLI -->
{{% codetab %}}

```bash
dapr init -k --set dapr_scheduler.cluster.inMemoryStorage=true
```

{{% /codetab %}}

 <!-- Helm -->
{{% codetab %}}

```bash
helm upgrade --install dapr dapr/dapr \
--version={{% dapr-latest-version short="true" %}} \
--namespace dapr-system \
--create-namespace \
--set dapr_scheduler.cluster.inMemoryStorage=true \
--wait
```

{{% /codetab %}}
{{< /tabs >}}

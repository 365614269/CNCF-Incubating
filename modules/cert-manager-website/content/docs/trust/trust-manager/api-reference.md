---
title: trust-manager API Reference
description: "trust-manager API documentation for custom resources"
---

Packages:

- [`trust.cert-manager.io/v1alpha1`](#trustcert-manageriov1alpha1)

# `trust.cert-manager.io/v1alpha1`

Resource Types:


- [Bundle](#bundle)




## `Bundle`







<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
      <td><b>apiVersion</b></td>
      <td>string</td>
      <td>trust.cert-manager.io/v1alpha1</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b>kind</b></td>
      <td>string</td>
      <td>Bundle</td>
      <td>true</td>
      </tr>
      <tr>
      <td><b><a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#objectmeta-v1-meta">metadata</a></b></td>
      <td>object</td>
      <td>Refer to the Kubernetes API documentation for the fields of the `metadata` field.</td>
      <td>true</td>
      </tr><tr>
        <td><b><a href="#bundlespec">spec</a></b></td>
        <td>object</td>
        <td>
          Desired state of the Bundle resource.
<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#bundlestatus">status</a></b></td>
        <td>object</td>
        <td>
          Status of the Bundle. This is set and managed automatically.
<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### `Bundle.spec`


Desired state of the Bundle resource.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#bundlespecsourcesindex">sources</a></b></td>
        <td>[]object</td>
        <td>
          Sources is a set of references to data whose data will sync to the target.
<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#bundlespectarget">target</a></b></td>
        <td>object</td>
        <td>
          Target is the target location in all namespaces to sync source data to.
<br/>
        </td>
        <td>true</td>
      </tr></tbody>
</table>


### `Bundle.spec.sources[index]`


BundleSource is the set of sources whose data will be appended and synced to
the BundleTarget in all Namespaces.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#bundlespecsourcesindexconfigmap">configMap</a></b></td>
        <td>object</td>
        <td>
          ConfigMap is a reference (by name) to a ConfigMap's `data` key(s), or to a
list of ConfigMap's `data` key(s) using label selector, in the trust Namespace.
<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>inLine</b></td>
        <td>string</td>
        <td>
          InLine is a simple string to append as the source data.
<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#bundlespecsourcesindexsecret">secret</a></b></td>
        <td>object</td>
        <td>
          Secret is a reference (by name) to a Secret's `data` key(s), or to a
list of Secret's `data` key(s) using label selector, in the trust Namespace.
<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>useDefaultCAs</b></td>
        <td>boolean</td>
        <td>
          UseDefaultCAs, when true, requests the default CA bundle to be used as a source.
Default CAs are available if trust-manager was installed via Helm
or was otherwise set up to include a package-injecting init container by using the
"--default-package-location" flag when starting the trust-manager controller.
If default CAs were not configured at start-up, any request to use the default
CAs will fail.
The version of the default CA package which is used for a Bundle is stored in the
defaultCAPackageVersion field of the Bundle's status field.
<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### `Bundle.spec.sources[index].configMap`


ConfigMap is a reference (by name) to a ConfigMap's `data` key(s), or to a
list of ConfigMap's `data` key(s) using label selector, in the trust Namespace.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>includeAllKeys</b></td>
        <td>boolean</td>
        <td>
          IncludeAllKeys is a flag to include all keys in the object's `data` field to be used. False by default.
This field must not be true when `Key` is set.
<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          Key of the entry in the object's `data` field to be used.
<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>name</b></td>
        <td>string</td>
        <td>
          Name is the name of the source object in the trust Namespace.
This field must be left empty when `selector` is set
<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#bundlespecsourcesindexconfigmapselector">selector</a></b></td>
        <td>object</td>
        <td>
          Selector is the label selector to use to fetch a list of objects. Must not be set
when `Name` is set.
<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### `Bundle.spec.sources[index].configMap.selector`


Selector is the label selector to use to fetch a list of objects. Must not be set
when `Name` is set.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#bundlespecsourcesindexconfigmapselectormatchexpressionsindex">matchExpressions</a></b></td>
        <td>[]object</td>
        <td>
          matchExpressions is a list of label selector requirements. The requirements are ANDed.
<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>matchLabels</b></td>
        <td>map[string]string</td>
        <td>
          matchLabels is a map of key-value pairs. A single key-value in the matchLabels
map is equivalent to an element of matchExpressions, whose key field is "key", the
operator is "In", and the values array contains only "value". The requirements are ANDed.
<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### `Bundle.spec.sources[index].configMap.selector.matchExpressions[index]`


A label selector requirement is a selector that contains values, a key, and an operator that
relates the key and values.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          key is the label key that the selector applies to.
<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>string</td>
        <td>
          operator represents a key's relationship to a set of values.
Valid operators are In, NotIn, Exists and DoesNotExist.
<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          values is an array of string values. If the operator is In or NotIn,
the values array must be non-empty. If the operator is Exists or DoesNotExist,
the values array must be empty. This array is replaced during a strategic
merge patch.
<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### `Bundle.spec.sources[index].secret`


Secret is a reference (by name) to a Secret's `data` key(s), or to a
list of Secret's `data` key(s) using label selector, in the trust Namespace.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>includeAllKeys</b></td>
        <td>boolean</td>
        <td>
          IncludeAllKeys is a flag to include all keys in the object's `data` field to be used. False by default.
This field must not be true when `Key` is set.
<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          Key of the entry in the object's `data` field to be used.
<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>name</b></td>
        <td>string</td>
        <td>
          Name is the name of the source object in the trust Namespace.
This field must be left empty when `selector` is set
<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#bundlespecsourcesindexsecretselector">selector</a></b></td>
        <td>object</td>
        <td>
          Selector is the label selector to use to fetch a list of objects. Must not be set
when `Name` is set.
<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### `Bundle.spec.sources[index].secret.selector`


Selector is the label selector to use to fetch a list of objects. Must not be set
when `Name` is set.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#bundlespecsourcesindexsecretselectormatchexpressionsindex">matchExpressions</a></b></td>
        <td>[]object</td>
        <td>
          matchExpressions is a list of label selector requirements. The requirements are ANDed.
<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>matchLabels</b></td>
        <td>map[string]string</td>
        <td>
          matchLabels is a map of key-value pairs. A single key-value in the matchLabels
map is equivalent to an element of matchExpressions, whose key field is "key", the
operator is "In", and the values array contains only "value". The requirements are ANDed.
<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### `Bundle.spec.sources[index].secret.selector.matchExpressions[index]`


A label selector requirement is a selector that contains values, a key, and an operator that
relates the key and values.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          key is the label key that the selector applies to.
<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>string</td>
        <td>
          operator represents a key's relationship to a set of values.
Valid operators are In, NotIn, Exists and DoesNotExist.
<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          values is an array of string values. If the operator is In or NotIn,
the values array must be non-empty. If the operator is Exists or DoesNotExist,
the values array must be empty. This array is replaced during a strategic
merge patch.
<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### `Bundle.spec.target`


Target is the target location in all namespaces to sync source data to.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#bundlespectargetadditionalformats">additionalFormats</a></b></td>
        <td>object</td>
        <td>
          AdditionalFormats specifies any additional formats to write to the target
<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#bundlespectargetconfigmap">configMap</a></b></td>
        <td>object</td>
        <td>
          ConfigMap is the target ConfigMap in Namespaces that all Bundle source
data will be synced to.
<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#bundlespectargetnamespaceselector">namespaceSelector</a></b></td>
        <td>object</td>
        <td>
          NamespaceSelector will, if set, only sync the target resource in
Namespaces which match the selector.
<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#bundlespectargetsecret">secret</a></b></td>
        <td>object</td>
        <td>
          Secret is the target Secret that all Bundle source data will be synced to.
Using Secrets as targets is only supported if enabled at trust-manager startup.
By default, trust-manager has no permissions for writing to secrets and can only read secrets in the trust namespace.
<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### `Bundle.spec.target.additionalFormats`


AdditionalFormats specifies any additional formats to write to the target

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#bundlespectargetadditionalformatsjks">jks</a></b></td>
        <td>object</td>
        <td>
          JKS requests a JKS-formatted binary trust bundle to be written to the target.
The bundle has "changeit" as the default password.
For more information refer to this link https://cert-manager.io/docs/faq/#keystore-passwords
Deprecated: Writing JKS is subject for removal. Please migrate to PKCS12.
PKCS#12 trust stores created by trust-manager are compatible with Java.
<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#bundlespectargetadditionalformatspkcs12">pkcs12</a></b></td>
        <td>object</td>
        <td>
          PKCS12 requests a PKCS12-formatted binary trust bundle to be written to the target.

The bundle is by default created without a password.
For more information refer to this link https://cert-manager.io/docs/faq/#keystore-passwords
<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### `Bundle.spec.target.additionalFormats.jks`


JKS requests a JKS-formatted binary trust bundle to be written to the target.
The bundle has "changeit" as the default password.
For more information refer to this link https://cert-manager.io/docs/faq/#keystore-passwords
Deprecated: Writing JKS is subject for removal. Please migrate to PKCS12.
PKCS#12 trust stores created by trust-manager are compatible with Java.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          Key is the key of the entry in the object's `data` field to be used.
<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>password</b></td>
        <td>string</td>
        <td>
          Password for JKS trust store
<br/>
          <br/>
            <i>Default</i>: changeit<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### `Bundle.spec.target.additionalFormats.pkcs12`


PKCS12 requests a PKCS12-formatted binary trust bundle to be written to the target.

The bundle is by default created without a password.
For more information refer to this link https://cert-manager.io/docs/faq/#keystore-passwords

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          Key is the key of the entry in the object's `data` field to be used.
<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>password</b></td>
        <td>string</td>
        <td>
          Password for PKCS12 trust store
<br/>
          <br/>
            <i>Default</i>: <br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>profile</b></td>
        <td>enum</td>
        <td>
          Profile specifies the certificate encryption algorithms and the HMAC algorithm
used to create the PKCS12 trust store.

If provided, allowed values are:
`LegacyRC2`: Deprecated. Not supported by default in OpenSSL 3 or Java 20.
`LegacyDES`: Less secure algorithm. Use this option for maximal compatibility.
`Modern2023`: Secure algorithm. Use this option in case you have to always use secure algorithms (e.g. because of company policy).

Default value is `LegacyRC2` for backward compatibility.
<br/>
          <br/>
            <i>Enum</i>: LegacyRC2, LegacyDES, Modern2023<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### `Bundle.spec.target.configMap`


ConfigMap is the target ConfigMap in Namespaces that all Bundle source
data will be synced to.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          Key is the key of the entry in the object's `data` field to be used.
<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#bundlespectargetconfigmapmetadata">metadata</a></b></td>
        <td>object</td>
        <td>
          Metadata is an optional set of labels and annotations to be copied to the target.
<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### `Bundle.spec.target.configMap.metadata`


Metadata is an optional set of labels and annotations to be copied to the target.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>annotations</b></td>
        <td>map[string]string</td>
        <td>
          Annotations is a key value map to be copied to the target.
<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>labels</b></td>
        <td>map[string]string</td>
        <td>
          Labels is a key value map to be copied to the target.
<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### `Bundle.spec.target.namespaceSelector`


NamespaceSelector will, if set, only sync the target resource in
Namespaces which match the selector.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#bundlespectargetnamespaceselectormatchexpressionsindex">matchExpressions</a></b></td>
        <td>[]object</td>
        <td>
          matchExpressions is a list of label selector requirements. The requirements are ANDed.
<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>matchLabels</b></td>
        <td>map[string]string</td>
        <td>
          matchLabels is a map of key-value pairs. A single key-value in the matchLabels
map is equivalent to an element of matchExpressions, whose key field is "key", the
operator is "In", and the values array contains only "value". The requirements are ANDed.
<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### `Bundle.spec.target.namespaceSelector.matchExpressions[index]`


A label selector requirement is a selector that contains values, a key, and an operator that
relates the key and values.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          key is the label key that the selector applies to.
<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>operator</b></td>
        <td>string</td>
        <td>
          operator represents a key's relationship to a set of values.
Valid operators are In, NotIn, Exists and DoesNotExist.
<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>values</b></td>
        <td>[]string</td>
        <td>
          values is an array of string values. If the operator is In or NotIn,
the values array must be non-empty. If the operator is Exists or DoesNotExist,
the values array must be empty. This array is replaced during a strategic
merge patch.
<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### `Bundle.spec.target.secret`


Secret is the target Secret that all Bundle source data will be synced to.
Using Secrets as targets is only supported if enabled at trust-manager startup.
By default, trust-manager has no permissions for writing to secrets and can only read secrets in the trust namespace.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>key</b></td>
        <td>string</td>
        <td>
          Key is the key of the entry in the object's `data` field to be used.
<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b><a href="#bundlespectargetsecretmetadata">metadata</a></b></td>
        <td>object</td>
        <td>
          Metadata is an optional set of labels and annotations to be copied to the target.
<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### `Bundle.spec.target.secret.metadata`


Metadata is an optional set of labels and annotations to be copied to the target.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>annotations</b></td>
        <td>map[string]string</td>
        <td>
          Annotations is a key value map to be copied to the target.
<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>labels</b></td>
        <td>map[string]string</td>
        <td>
          Labels is a key value map to be copied to the target.
<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### `Bundle.status`


Status of the Bundle. This is set and managed automatically.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b><a href="#bundlestatusconditionsindex">conditions</a></b></td>
        <td>[]object</td>
        <td>
          List of status conditions to indicate the status of the Bundle.
Known condition types are `Bundle`.
<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b>defaultCAVersion</b></td>
        <td>string</td>
        <td>
          DefaultCAPackageVersion, if set and non-empty, indicates the version information
which was retrieved when the set of default CAs was requested in the bundle
source. This should only be set if useDefaultCAs was set to "true" on a source,
and will be the same for the same version of a bundle with identical certificates.
<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>


### `Bundle.status.conditions[index]`


Condition contains details for one aspect of the current state of this API Resource.

<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
            <th>Required</th>
        </tr>
    </thead>
    <tbody><tr>
        <td><b>lastTransitionTime</b></td>
        <td>string</td>
        <td>
          lastTransitionTime is the last time the condition transitioned from one status to another.
This should be when the underlying condition changed.  If that is not known, then using the time when the API field changed is acceptable.
<br/>
          <br/>
            <i>Format</i>: date-time<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>message</b></td>
        <td>string</td>
        <td>
          message is a human readable message indicating details about the transition.
This may be an empty string.
<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>reason</b></td>
        <td>string</td>
        <td>
          reason contains a programmatic identifier indicating the reason for the condition's last transition.
Producers of specific condition types may define expected values and meanings for this field,
and whether the values are considered a guaranteed API.
The value should be a CamelCase string.
This field may not be empty.
<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>status</b></td>
        <td>enum</td>
        <td>
          status of the condition, one of True, False, Unknown.
<br/>
          <br/>
            <i>Enum</i>: True, False, Unknown<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>type</b></td>
        <td>string</td>
        <td>
          type of condition in CamelCase or in foo.example.com/CamelCase.
<br/>
        </td>
        <td>true</td>
      </tr><tr>
        <td><b>observedGeneration</b></td>
        <td>integer</td>
        <td>
          observedGeneration represents the .metadata.generation that the condition was set based upon.
For instance, if .metadata.generation is currently 12, but the .status.conditions[x].observedGeneration is 9, the condition is out of date
with respect to the current state of the instance.
<br/>
          <br/>
            <i>Format</i>: int64<br/>
            <i>Minimum</i>: 0<br/>
        </td>
        <td>false</td>
      </tr></tbody>
</table>

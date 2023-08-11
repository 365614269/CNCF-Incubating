# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
#
# AWS resources to manage
#
from c7n.provider import clouds

LOADED = set()


def load_resources(resource_types=('*',)):
    pmap = {}
    for r in resource_types:
        parts = r.split('.', 1)
        # support aws.*
        if parts[-1] == '*':
            r = '*'
        pmap.setdefault(parts[0], []).append(r)

    load_providers(set(pmap))
    missing = []
    for pname, p in clouds.items():
        if '*' in pmap:
            p.get_resource_types(('*',))
        elif pname in pmap:
            _, not_found = p.get_resource_types(pmap[pname])
            missing.extend(not_found)
    return missing


def should_load_provider(name, provider_types, no_wild=False):
    global LOADED
    if (name not in LOADED and
        (('*' in provider_types and not no_wild)
         or name in provider_types)):
        return True
    return False


PROVIDER_NAMES = ('aws', 'azure', 'gcp', 'k8s', 'openstack', 'awscc', 'tencentcloud', 'terraform', 'oci')


def load_available(resources=True):
    """Load available installed providers

    Unlike load_resources() this will catch ImportErrors on uninstalled
    providers.
    """
    found = []
    for provider in PROVIDER_NAMES:
        try:
            load_providers((provider,))
        except ImportError: # pragma: no cover
            continue
        else:
            found.append(provider)
    if resources:
        load_resources(['%s.*' % s for s in found])
    return found


def load_providers(provider_types):
    global LOADED

    # Even though we're lazy loading resources we still need to import
    # those that are making available generic filters/actions
    if should_load_provider('aws', provider_types):
        import c7n.resources.securityhub
        import c7n.resources.sfn
        import c7n.resources.ssm # NOQA

    if should_load_provider('awscc', provider_types):
        from c7n_awscc.entry import initialize_awscc
        initialize_awscc()

    if should_load_provider('azure', provider_types):
        from c7n_azure.entry import initialize_azure
        initialize_azure()

    if should_load_provider('gcp', provider_types):
        from c7n_gcp.entry import initialize_gcp
        initialize_gcp()

    if should_load_provider('k8s', provider_types):
        from c7n_kube.entry import initialize_kube
        initialize_kube()

    if should_load_provider('openstack', provider_types):
        from c7n_openstack.entry import initialize_openstack
        initialize_openstack()

    if should_load_provider('tencentcloud', provider_types):
        from c7n_tencentcloud.entry import initialize_tencentcloud
        initialize_tencentcloud()

    if should_load_provider('terraform', provider_types, no_wild=True):
        from c7n_left.entry import initialize_iac
        initialize_iac()

    if should_load_provider('oci', provider_types):
        from c7n_oci.entry import initialize_oci
        initialize_oci()

    if should_load_provider('c7n', provider_types):
        from c7n import data  # noqa

    LOADED.update(provider_types)

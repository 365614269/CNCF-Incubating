# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import logging

from c7n_azure import constants
from c7n_azure.provider import resources
from c7n_azure.query import ChildResourceManager, ChildTypeInfo

log = logging.getLogger('custodian.azure.keyvault.certificates')


@resources.register('keyvault-certificate')
class KeyVaultCertificate(ChildResourceManager):
    """Key Vault Certificate Resource

    :example:

    This policy will find all certificates that will expire in next 30 days

    .. code-block:: yaml

        policies:
          - name: keyvault-certificates
            description:
              List all certificates expiring in next 30 days
            resource: azure.keyvault-certificate
            filters:
              - type: value
                key: attributes.exp
                value_type: expiration
                op: lt
                value: 30

    """

    class resource_type(ChildTypeInfo):
        doc_groups = ['Security']

        resource = constants.VAULT_AUTH_ENDPOINT
        service = 'azure.keyvault.certificates'
        client = 'CertificateClient'
        enum_spec = (None, 'list_properties_of_certificates', None)

        parent_manager_name = 'keyvault'
        raise_on_exception = False

        default_report_fields = (
            'id',
            'attributes.expires'
        )

        keyvault_child = True

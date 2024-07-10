# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from c7n.actions.core import BaseAction
from c7n.manager import resources as c7n_resources
from c7n.query import QueryResourceManager, TypeInfo
from c7n.utils import local_session, type_schema
from c7n.tags import RemoveTag, Tag, TagActionFilter, TagDelayedAction


@c7n_resources.register('networkmanager-core')
class CoreNetwork(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'networkmanager'
        enum_spec = ('list_core_networks', 'CoreNetworks', None)
        detail_spec = (
            'get_core_network', 'CoreNetworkId',
            'CoreNetworkId', None)
        arn = 'CoreNetworkArn'
        name = 'CoreNetworkId'
        id = 'CoreNetworkId'
        date = 'CreatedAt'
        config_type = None
        cfn_type = 'AWS::NetworkManager::CoreNetwork'
        permissions_augment = ("networkmanager:ListTagsForResource",)


CoreNetwork.filter_registry.register('marked-for-op', TagActionFilter)


@c7n_resources.register('networkmanager-global')
class GlobalNetwork(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'networkmanager'
        enum_spec = ('describe_global_networks', 'GlobalNetworks', None)
        arn = 'GlobalNetworkArn'
        name = 'GlobalNetworkId'
        id = 'GlobalNetworkId'
        date = 'CreatedAt'
        config_type = cfn_type = 'AWS::NetworkManager::GlobalNetwork'
        permissions_augment = ("networkmanager:ListTagsForResource",)


GlobalNetwork.filter_registry.register('marked-for-op', TagActionFilter)


@GlobalNetwork.action_registry.register('tag')
@CoreNetwork.action_registry.register('tag')
class TagNetwork(Tag):
    """Action to tag a networkmanager resource
    """
    permissions = ('networkmanager:TagResource',)

    def process_resource_set(self, client, resource_set, tags):
        mid = self.manager.resource_type.arn
        for r in resource_set:
            try:
                client.tag_resource(ResourceArn=r[mid], Tags=tags)
            except client.exceptions.ResourceNotFoundException:
                continue


@GlobalNetwork.action_registry.register('remove-tag')
@CoreNetwork.action_registry.register('remove-tag')
class RemoveTagNetwork(RemoveTag):
    """Action to remove a tag from networkmanager resource
    """
    permissions = ('networkmanager:UntagResource',)

    def process_resource_set(self, client, resource_set, tag_keys):
        mid = self.manager.resource_type.arn
        for r in resource_set:
            try:
                client.untag_resource(ResourceArn=r[mid], TagKeys=tag_keys)
            except client.exceptions.ResourceNotFoundException:
                continue


@GlobalNetwork.action_registry.register('mark-for-op')
@CoreNetwork.action_registry.register('mark-for-op')
class NetworkMarkForOp(TagDelayedAction):
    """Mark Network for deferred action

    :example:

    .. code-block:: yaml

        policies:
          - name: core-network-invalid-tag-mark
            resource: networkmanager-core
            filters:
              - "tag:InvalidTag": present
            actions:
              - type: mark-for-op
                op: delete
                days: 1
    """
    permissions = ('networkmanager:TagResource',)


@CoreNetwork.action_registry.register('delete')
class DeleteCoreNetwork(BaseAction):
    """Action to delete a networkmanager core network
    """
    schema = type_schema('delete')
    permissions = ('networkmanager:DeleteCoreNetwork',)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('networkmanager')

        for r in resources:
            try:
                client.delete_core_network(CoreNetworkId=r['CoreNetworkId'])
            except client.exceptions.ResourceNotFoundException:
                continue


@GlobalNetwork.action_registry.register('delete')
class DeleteGlobalNetwork(BaseAction):
    """Action to delete a networkmanager global network
    """
    schema = type_schema('delete')
    permissions = ('networkmanager:DeleteGlobalNetwork',)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('networkmanager')

        for r in resources:
            try:
                client.delete_global_network(GlobalNetworkId=r['GlobalNetworkId'])
            except client.exceptions.ResourceNotFoundException:
                continue

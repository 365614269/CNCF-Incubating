from c7n.actions import BaseAction
from c7n.manager import resources
from c7n.query import (
    ChildDescribeSource,
    ChildResourceManager,
    DescribeWithResourceTags,
    QueryResourceManager,
    TypeInfo,
)
from c7n.resources.aws import shape_schema
from c7n.tags import RemoveTag, Tag, TagActionFilter, TagDelayedAction, universal_augment
from c7n.utils import get_retry, local_session, type_schema


SYSTEM_KEYSPACES = [
    "system",
    "system_schema",
    "system_schema_mcs",
    "system_multiregion_info",
]


class DescribeKeyspaces(DescribeWithResourceTags):

    def get_permissions(self):
        perms = super().get_permissions()
        perms.remove('cassandra:GetKeyspace')
        return perms

    def get_resources(self, resource_ids, cache=True):
        return [
            r for r in super().get_resources(resource_ids, cache)
            if r['keyspaceName'] not in SYSTEM_KEYSPACES
        ]

    def resources(self, query):
        return [r for r in super().resources(query)
                if r['keyspaceName'] not in SYSTEM_KEYSPACES]


@resources.register('keyspace')
class Keyspace(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'keyspaces'
        arn_type = 'keyspace'
        permission_prefix = 'cassandra'
        permissions_enum = ('cassandra:Select',)
        enum_spec = ('list_keyspaces', 'keyspaces', None)
        detail_spec = ('get_keyspace', 'keyspaceName', 'keyspaceName', None)
        id = 'keyspaceName'
        arn = 'resourceArn'
        name = 'keyspaceName'
        cfn_type = 'AWS::Cassandra::Keyspace'

    retry = staticmethod(get_retry(
        ("ConflictException", "InternalServerException",)
    ))
    source_mapping = {
        'describe': DescribeKeyspaces,
    }


Keyspace.filter_registry.register('marked-for-op', TagActionFilter)


@Keyspace.action_registry.register('tag')
class TagKeyspace(Tag):
    permissions = ('cassandra:TagResource', 'cassandra:TagMultiRegionResource')

    def process(self, resources):
        client = self.get_client()
        for r in resources:
            client.tag_resource(
                resourceArn=r['resourceArn'],
                tags=[{'key': k, 'value': v} for k, v in self.data.get('tags', {}).items()]
                )


@Keyspace.action_registry.register('mark-for-op')
class KeyspaceMark(TagDelayedAction):
    """Mark a Keyspace for future Custodian action

    :example:

    .. code-block:: yaml

            policies:
              - name: keyspace-mark-for-delete
                resource: keyspace
                filters:
                  - type: value
                    key: replicationStrategy
                    op: eq
                    value: SINGLE_REGION
                actions:
                  - type: mark-for-op
                    op: delete
                    days: 7
    """


@Keyspace.action_registry.register('remove-tag')
class RemoveTagKeyspace(RemoveTag):
    permissions = ('cassandra:UntagResource', 'cassandra:UnTagMultiRegionResource')

    def process(self, resources):
        client = self.get_client()
        tag_keys = self.data.get('tags', [])
        for r in resources:
            tags_to_remove = [
                {'key': t['Key'], 'value': t['Value']}
                for t in r['Tags'] if t['Key'] in tag_keys
            ]
            self.manager.retry(
                client.untag_resource,
                resourceArn=r['resourceArn'],
                tags=tags_to_remove
            )


@Keyspace.action_registry.register('update')
class UpdateKeyspace(BaseAction):
    schema = type_schema(
        'update',
        **shape_schema('keyspaces', 'UpdateKeyspaceRequest', drop_fields=('keyspaceName')),
        required=['replicationSpecification'],
    )
    permissions = ('cassandra:Alter', 'cassandra:AlterMultiRegionResource')

    def process(self, resources):
        client = local_session(self.manager.session_factory).client(
            self.manager.resource_type.service)
        params = dict(self.data)
        params.pop('type')
        for r in resources:
            client.update_keyspace(
                keyspaceName=r['keyspaceName'],
                **params
            )


@Keyspace.action_registry.register('delete')
class DeleteKeyspace(BaseAction):
    schema = type_schema('delete')
    permissions = ('cassandra:Drop', 'cassandra:DropMultiRegionResource')

    def process(self, resources):
        client = local_session(self.manager.session_factory).client(
            self.manager.resource_type.service)
        for r in resources:
            self.manager.retry(
                client.delete_keyspace,
                ignore_err_codes=('ResourceNotFoundException'),
                keyspaceName=r['keyspaceName'],
            )


class DescribeTables(ChildDescribeSource):

    def augment(self, resources):
        client = local_session(self.manager.session_factory).client(
            self.manager.resource_type.service)

        def _augment(r):
            details = self.manager.retry(
                client.get_table,
                keyspaceName=r['keyspaceName'],
                tableName=r['tableName']
            )
            r.update(details)
            return r

        resources = universal_augment(self.manager, super().augment(resources))
        return list(map(_augment, resources))


@resources.register('keyspace-table')
class Table(ChildResourceManager):

    class resource_type(TypeInfo):
        service = 'keyspaces'
        permission_prefix = 'cassandra'
        permissions_enum = ('cassandra:Select',)
        parent_spec = ('keyspace', 'keyspaceName', None)
        enum_spec = ('list_tables', 'tables', None)
        id = 'tableName'
        arn = 'resourceArn'
        name = 'tableName'
        cfn_type = 'AWS::Cassandra::Table'

    retry = staticmethod(get_retry(
        ("ConflictException", "InternalServerException",)
    ))
    source_mapping = {
        'describe-child': DescribeTables,
    }


@Table.action_registry.register('tag')
class TagTable(Tag):
    permissions = ('cassandra:TagResource', 'cassandra:TagMultiRegionResource')

    def process(self, resources):
        client = self.get_client()
        for r in resources:
            client.tag_resource(
                resourceArn=r['resourceArn'],
                tags=[{'key': k, 'value': v} for k, v in self.data.get('tags', {}).items()]
                )


@Table.action_registry.register('mark-for-op')
class TableMark(TagDelayedAction):
    """Mark a Table for future Custodian action

    :example:

    .. code-block:: yaml

            policies:
              - name: table-mark-for-delete
                resource: keyspace-table
                filters:
                  - type: value
                    key: encryptionSpecification.type
                    op: eq
                    value: AWS_OWNED_KMS_KEY
                actions:
                  - type: mark-for-op
                    op: delete
                    days: 7
    """


@Table.action_registry.register('remove-tag')
class RemoveTagTable(RemoveTag):
    permissions = ('cassandra:UntagResource', 'cassandra:UnTagMultiRegionResource')

    def process(self, resources):
        client = self.get_client()
        tag_keys = self.data.get('tags', [])
        for r in resources:
            tags_to_remove = [
                {'key': t['Key'], 'value': t['Value']}
                for t in r['Tags'] if t['Key'] in tag_keys
            ]
            self.manager.retry(
                client.untag_resource,
                resourceArn=r['resourceArn'],
                tags=tags_to_remove
            )


@Table.action_registry.register('update')
class UpdateTable(BaseAction):
    schema = type_schema(
        'update',
        **shape_schema(
            'keyspaces', 'UpdateTableRequest',
            drop_fields=('keyspaceName', 'tableName')
        ),
    )
    permissions = ('cassandra:Alter', 'cassandra:AlterMultiRegionResource')

    def process(self, resources):
        client = local_session(self.manager.session_factory).client(
            self.manager.resource_type.service)
        params = dict(self.data)
        params.pop('type')
        for r in resources:
            client.update_table(
                keyspaceName=r['keyspaceName'],
                tableName=r['tableName'],
                **params
            )


@Table.action_registry.register('delete')
class DeleteTable(BaseAction):
    schema = type_schema('delete')
    permissions = ('cassandra:Drop', 'cassandra:DropMultiRegionResource')

    def process(self, resources):
        client = local_session(self.manager.session_factory).client(
            self.manager.resource_type.service)
        for r in resources:
            self.manager.retry(
                client.delete_table,
                ignore_err_codes=('ResourceNotFoundException'),
                keyspaceName=r['keyspaceName'],
                tableName=r['tableName'],
            )

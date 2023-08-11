# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations
from datetime import datetime, timedelta

from c7n.manager import resources
from c7n.query import (
    QueryResourceManager, TypeInfo, DescribeSource, RetryPageIterator)
from c7n.actions import BaseAction
from c7n.tags import Tag, TagDelayedAction, RemoveTag, coalesce_copy_user_tags, TagActionFilter
from c7n.utils import type_schema, local_session, chunks
from c7n.filters import Filter
from c7n.filters.kms import KmsRelatedFilter
from c7n.filters.vpc import SubnetFilter
from c7n.filters.backup import ConsecutiveAwsBackupsFilter


class DescribeFSx(DescribeSource):

    def get_resources(self, ids):
        """Support server side filtering on arns
        """
        for n in range(len(ids)):
            if ids[n].startswith('arn:'):
                ids[n] = ids[n].rsplit('/', 1)[-1]
        params = {'FileSystemIds': ids}
        return self.query.filter(self.manager, **params)


@resources.register('fsx')
class FSx(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'fsx'
        enum_spec = ('describe_file_systems', 'FileSystems', None)
        name = id = 'FileSystemId'
        arn = "ResourceARN"
        date = 'CreationTime'
        cfn_type = 'AWS::FSx::FileSystem'

    source_mapping = {
        'describe': DescribeFSx
    }


@resources.register('fsx-backup')
class FSxBackup(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'fsx'
        enum_spec = ('describe_backups', 'Backups', None)
        name = id = 'BackupId'
        arn = "ResourceARN"
        date = 'CreationTime'


@FSxBackup.action_registry.register('delete')
class DeleteBackup(BaseAction):
    """
    Delete backups

    :example:

    .. code-block:: yaml

        policies:
            - name: delete-backups
              resource: fsx-backup
              filters:
                - type: value
                  value_type: age
                  key: CreationDate
                  value: 30
                  op: gt
              actions:
                - type: delete
    """
    permissions = ('fsx:DeleteBackup',)
    schema = type_schema('delete')

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('fsx')
        for r in resources:
            try:
                client.delete_backup(BackupId=r['BackupId'])
            except client.exceptions.BackupRestoring as e:
                self.log.warning(
                    'Unable to delete backup for: %s - %s - %s' % (
                        r['FileSystemId'], r['BackupId'], e))


FSxBackup.filter_registry.register('marked-for-op', TagActionFilter)

FSx.filter_registry.register('marked-for-op', TagActionFilter)


@FSxBackup.action_registry.register('mark-for-op')
@FSx.action_registry.register('mark-for-op')
class MarkForOpFileSystem(TagDelayedAction):

    permissions = ('fsx:TagResource',)


@FSxBackup.action_registry.register('tag')
@FSx.action_registry.register('tag')
class TagFileSystem(Tag):
    concurrency = 2
    batch_size = 5
    permissions = ('fsx:TagResource',)

    def process_resource_set(self, client, resources, tags):
        for r in resources:
            client.tag_resource(ResourceARN=r['ResourceARN'], Tags=tags)


@FSxBackup.action_registry.register('remove-tag')
@FSx.action_registry.register('remove-tag')
class UnTagFileSystem(RemoveTag):
    concurrency = 2
    batch_size = 5
    permissions = ('fsx:UntagResource',)

    def process_resource_set(self, client, resources, tag_keys):
        for r in resources:
            client.untag_resource(ResourceARN=r['ResourceARN'], TagKeys=tag_keys)


@FSx.action_registry.register('update')
class UpdateFileSystem(BaseAction):
    """
    Update FSx resource configurations

    :example:

    .. code-block:: yaml

        policies:
            - name: update-fsx-resource
              resource: fsx
              actions:
                - type: update
                  WindowsConfiguration:
                    AutomaticBackupRetentionDays: 1
                    DailyAutomaticBackupStartTime: '04:30'
                    WeeklyMaintenanceStartTime: '04:30'
                  LustreConfiguration:
                    WeeklyMaintenanceStartTime: '04:30'

    Reference: https://docs.aws.amazon.com/fsx/latest/APIReference/API_UpdateFileSystem.html
    """
    permissions = ('fsx:UpdateFileSystem',)

    schema = type_schema(
        'update',
        WindowsConfiguration={'type': 'object'},
        LustreConfiguration={'type': 'object'}
    )

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('fsx')
        for r in resources:
            client.update_file_system(
                FileSystemId=r['FileSystemId'],
                WindowsConfiguration=self.data.get('WindowsConfiguration', {}),
                LustreConfiguration=self.data.get('LustreConfiguration', {})
            )


@FSx.action_registry.register('backup')
class BackupFileSystem(BaseAction):
    """
    Create Backups of File Systems

    Tags are specified in key value pairs, e.g.: BackupSource: CloudCustodian

    :example:

    .. code-block:: yaml

        policies:
            - name: backup-fsx-resource
              comment: |
                  creates a backup of fsx resources and
                  copies tags from file system to the backup
              resource: fsx
              actions:
                - type: backup
                  copy-tags: True
                  tags:
                    BackupSource: CloudCustodian

            - name: backup-fsx-resource-copy-specific-tags
              comment: |
                  creates a backup of fsx resources and
                  copies tags from file system to the backup
              resource: fsx
              actions:
                - type: backup
                  copy-tags:
                    - Application
                    - Owner
                    # or use '*' to specify all tags
                  tags:
                    BackupSource: CloudCustodian
    """

    permissions = ('fsx:CreateBackup',)

    schema = type_schema(
        'backup',
        **{
            'tags': {
                'type': 'object'
            },
            'copy-tags': {
                'oneOf': [
                    {
                        'type': 'boolean'
                    },
                    {
                        'type': 'array',
                        'items': {
                            'type': 'string'
                        }
                    }
                ]
            }
        }
    )

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('fsx')
        user_tags = self.data.get('tags', {})
        copy_tags = self.data.get('copy-tags', True)
        for r in resources:
            tags = coalesce_copy_user_tags(r, copy_tags, user_tags)
            try:
                if tags:
                    client.create_backup(
                        FileSystemId=r['FileSystemId'],
                        Tags=tags
                    )
                else:
                    client.create_backup(
                        FileSystemId=r['FileSystemId']
                    )
            except client.exceptions.BackupInProgress as e:
                self.log.warning(
                    'Unable to create backup for: %s - %s' % (r['FileSystemId'], e))


@FSx.action_registry.register('delete')
class DeleteFileSystem(BaseAction):
    """
    Delete Filesystems

    :example:

    .. code-block:: yaml

        policies:
            - name: delete-fsx-instance-with-snapshot
              resource: fsx
              filters:
                - FileSystemId: fs-1234567890123
              actions:
                - type: delete
                  copy-tags:
                    - Application
                    - Owner
                  tags:
                    DeletedBy: CloudCustodian

            - name: delete-fsx-instance-skip-snapshot
              resource: fsx
              filters:
                - FileSystemId: fs-1234567890123
              actions:
                - type: delete
                  skip-snapshot: True

    """

    permissions = ('fsx:DeleteFileSystem',)

    schema = type_schema(
        'delete',
        **{
            'skip-snapshot': {'type': 'boolean'},
            'tags': {'type': 'object'},
            'copy-tags': {
                'oneOf': [
                    {
                        'type': 'array',
                        'items': {
                            'type': 'string'
                        }
                    },
                    {
                        'type': 'boolean'
                    }
                ]
            }
        }
    )

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('fsx')

        skip_snapshot = self.data.get('skip-snapshot', False)
        copy_tags = self.data.get('copy-tags', True)
        user_tags = self.data.get('tags', [])

        for r in resources:
            tags = coalesce_copy_user_tags(r, copy_tags, user_tags)
            config = {'SkipFinalBackup': skip_snapshot}
            if tags and not skip_snapshot:
                config['FinalBackupTags'] = tags
            try:
                client.delete_file_system(
                    FileSystemId=r['FileSystemId'],
                    WindowsConfiguration=config
                )
            except client.exceptions.BadRequest as e:
                self.log.warning('Unable to delete: %s - %s' % (r['FileSystemId'], e))


@FSx.filter_registry.register('kms-key')
class KmsFilter(KmsRelatedFilter):

    RelatedIdsExpression = 'KmsKeyId'


@FSxBackup.filter_registry.register('kms-key')
class KmsFilterFsxBackup(KmsRelatedFilter):

    RelatedIdsExpression = 'KmsKeyId'


@FSx.filter_registry.register('consecutive-backups')
class ConsecutiveBackups(Filter):
    """Returns consecutive daily FSx backups, which are equal to/or greater than n days.
    :Example:

    .. code-block:: yaml

            policies:
              - name: fsx-daily-backup-count
                resource: fsx
                filters:
                  - type: consecutive-backups
                    days: 5
                actions:
                  - notify
    """
    schema = type_schema('consecutive-backups',
                         days={'type': 'number', 'minimum': 1},
                         required=['days'])
    permissions = ('fsx:DescribeBackups', 'fsx:DescribeVolumes',)
    annotation = 'c7n:FSxBackups'

    def describe_backups(self, client, name=None, filters=[]):
        desc_backups = []
        try:
            paginator = client.get_paginator('describe_backups')
            paginator.PAGE_ITERATOR_CLS = RetryPageIterator
            desc_backups = paginator.paginate(Filters=[
                {
                    'Name': name,
                    'Values': filters,
                }]).build_full_result().get('Backups', [])
        except Exception as err:
            self.log.warning(
                'Unable to describe backups for ids: %s - %s' % (filters, err))
        return desc_backups

    def ontap_process_resource_set(self, client, resources):
        ontap_fid_backups = {}
        ontap_backups = []
        ontap_fids = [r['FileSystemId'] for r in resources]
        if ontap_fids:
            ontap_volumes = client.describe_volumes(Filters=[
                {
                    'Name': 'file-system-id',
                    'Values': ontap_fids,
                }])
            ontap_vids = [v['VolumeId'] for v in ontap_volumes['Volumes']]
            for ovid in chunks(ontap_vids, 20):
                ontap_backups = self.describe_backups(client, 'volume-id', ovid)
            if ontap_backups:
                for ontap in ontap_backups:
                    ontap_fid_backups.setdefault(ontap['Volume']
                                           ['FileSystemId'], []).append(ontap)
        for r in resources:
            r[self.annotation] = ontap_fid_backups.get(r['FileSystemId'], [])

    def nonontap_process_resource_set(self, client, resources):
        fid_backups = {}
        nonontap_backups = []
        nonontap_fids = [r['FileSystemId'] for r in resources]
        if nonontap_fids:
            for nonontap_fid in chunks(nonontap_fids, 20):
                nonontap_backups = self.describe_backups(client, 'file-system-id', nonontap_fid)
            if nonontap_backups:
                for nonontap in nonontap_backups:
                    fid_backups.setdefault(nonontap['FileSystem']
                                           ['FileSystemId'], []).append(nonontap)
        for r in resources:
            r[self.annotation] = fid_backups.get(r['FileSystemId'], [])

    def process(self, resources, event=None):
        client = local_session(self.manager.session_factory).client('fsx')
        results = []
        ontap_resource_set, nonontap_resource_set = [], []
        retention = self.data.get('days')
        utcnow = datetime.utcnow()
        expected_dates = set()
        for days in range(1, retention + 1):
            expected_dates.add((utcnow - timedelta(days=days)).strftime('%Y-%m-%d'))

        for r in resources:
            if self.annotation not in r:
                if r['FileSystemType'] == 'ONTAP':
                    ontap_resource_set.append(r)
                else:
                    nonontap_resource_set.append(r)

        if ontap_resource_set:
            self.ontap_process_resource_set(client, ontap_resource_set)
        if nonontap_resource_set:
            self.nonontap_process_resource_set(client, nonontap_resource_set)

        for r in resources:
            backup_dates = set()
            for backup in r[self.annotation]:
                if backup['Lifecycle'] == 'AVAILABLE':
                    backup_dates.add(backup['CreationTime'].strftime('%Y-%m-%d'))
            if expected_dates.issubset(backup_dates):
                results.append(r)
        return results


@FSx.filter_registry.register('subnet')
class Subnet(SubnetFilter):

    RelatedIdsExpression = 'SubnetIds[]'

FSx.filter_registry.register('consecutive-aws-backups', ConsecutiveAwsBackupsFilter)

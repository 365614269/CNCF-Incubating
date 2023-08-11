# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import json
from c7n.manager import resources
from c7n.actions import BaseAction, RemovePolicyBase
from c7n.exceptions import PolicyValidationError
from c7n.filters import iamaccess
from c7n.query import QueryResourceManager, TypeInfo
from c7n.filters.kms import KmsRelatedFilter
from c7n.tags import RemoveTag, Tag, TagActionFilter, TagDelayedAction, Action
from c7n.utils import local_session, type_schema, jmespath_search
from c7n.filters.policystatement import HasStatementFilter


@resources.register('secrets-manager')
class SecretsManager(QueryResourceManager):

    permissions = ('secretsmanager:ListSecretVersionIds',)

    class resource_type(TypeInfo):
        service = 'secretsmanager'
        enum_spec = ('list_secrets', 'SecretList', None)
        detail_spec = ('describe_secret', 'SecretId', 'Name', None)
        config_type = cfn_type = 'AWS::SecretsManager::Secret'
        name = id = 'Name'
        arn = 'ARN'


SecretsManager.filter_registry.register('marked-for-op', TagActionFilter)


@SecretsManager.filter_registry.register('cross-account')
class CrossAccountAccessFilter(iamaccess.CrossAccountAccessFilter):

    policy_annotation = "c7n:AccessPolicy"
    permissions = ("secretsmanager:GetResourcePolicy",)

    def process(self, resources, event=None):
        self.client = local_session(self.manager.session_factory).client('secretsmanager')
        return super(CrossAccountAccessFilter, self).process(resources)

    def get_resource_policy(self, r):
        if self.policy_annotation in r:
            return r[self.policy_annotation]
        r[self.policy_annotation] = p = self.client.get_resource_policy(
            SecretId=r['Name']).get('ResourcePolicy', None)
        return p


@SecretsManager.filter_registry.register('kms-key')
class KmsFilter(KmsRelatedFilter):
    RelatedIdsExpression = 'KmsKeyId'


@SecretsManager.filter_registry.register('has-statement')
class HasStatementFilter(HasStatementFilter):

    def get_std_format_args(self, secret):
        return {
            'secret_arn': secret['ARN'],
            'account_id': self.manager.config.account_id,
            'region': self.manager.config.region
        }

    def process(self, resources, event=None):
        self.client = local_session(self.manager.session_factory).client('secretsmanager')
        for r in resources:
            try:
                policy = self.client.get_resource_policy(SecretId=r['Name'])
                if policy.get('ResourcePolicy'):
                    r['Policy'] = policy['ResourcePolicy']
            except self.client.exceptions.ResourceNotFoundException:
                continue

        return list(filter(None, map(self.process_resource, resources)))


@SecretsManager.action_registry.register('tag')
class TagSecretsManagerResource(Tag):
    """Action to create tag(s) on a Secret resource

    :example:

    .. code-block:: yaml

        policies:
            - name: tag-secret
              resource: secrets-manager
              actions:
                - type: tag
                  key: tag-key
                  value: tag-value
    """

    permissions = ('secretsmanager:TagResource',)

    def process_resource_set(self, client, resources, new_tags):
        for r in resources:
            tags = {t['Key']: t['Value'] for t in r.get('Tags', ())}
            for t in new_tags:
                tags[t['Key']] = t['Value']
            formatted_tags = [{'Key': k, 'Value': v} for k, v in tags.items()]
            client.tag_resource(SecretId=r['ARN'], Tags=formatted_tags)


@SecretsManager.action_registry.register('remove-tag')
class RemoveTagSecretsManagerResource(RemoveTag):
    """Action to remove tag(s) on a Secret resource

    :example:

    .. code-block:: yaml

        policies:
            - name: untag-secret
              resource: secrets-manager
              actions:
                - type: remove-tag
                  tags: ['tag-to-be-removed']
    """

    permissions = ('secretsmanager:UntagResource',)

    def process_resource_set(self, client, resources, keys):
        for r in resources:
            client.untag_resource(SecretId=r['ARN'], TagKeys=keys)


@SecretsManager.action_registry.register('mark-for-op')
class MarkSecretForOp(TagDelayedAction):
    """Action to mark a Secret resource for deferred action :example:

    .. code-block:: yaml

        policies:
            - name: mark-secret-for-delete
              resource: secrets-manager
              actions:
                - type: mark-for-op
                  op: tag
                  days: 1
    """


@SecretsManager.action_registry.register('delete')
class DeleteSecretsManager(BaseAction):
    """Delete a secret and all of its versions.
    The recovery window is the number of days from 7 to 30 that
    Secrets Manager waits before permanently deleting the secret
    with default as 30

    :example:

    .. code-block:: yaml

            policies:
              - name: delete-cross-account-secrets
                resource: aws.secrets-manager
                filters:
                  - type: cross-account
                actions:
                  - type: delete
                    recovery_window: 10
    """

    schema = type_schema('delete', recovery_window={'type': 'integer'})
    permissions = ('secretsmanager:DeleteSecret',)

    def process(self, resources):
        client = local_session(
            self.manager.session_factory).client('secretsmanager')

        for r in resources:
            if 'ReplicationStatus' in r:
                rep_regions = jmespath_search('ReplicationStatus[*].Region', r)
                self.manager.retry(client.remove_regions_from_replication,
                  SecretId=r['ARN'], RemoveReplicaRegions=rep_regions)
            self.manager.retry(client.delete_secret,
              SecretId=r['ARN'], RecoveryWindowInDays=self.data.get('recovery_window', 30))


@SecretsManager.action_registry.register('remove-statements')
class SecretsManagerRemovePolicyStatement(RemovePolicyBase):
    """
    Action to remove resource based policy statements from secrets manager

    :example:

    .. code-block:: yaml

        policies:
          - name: secrets-manager-cross-account
            resource: aws.secrets-manager
            filters:
              - type: cross-account
            actions:
              - type: remove-statements
                statement_ids: matched
    """

    permissions = ("secretsmanager:DeleteResourcePolicy", "secretsmanager:PutResourcePolicy",)

    def validate(self):
        for f in self.manager.iter_filters():
            if isinstance(f, CrossAccountAccessFilter):
                return self
        raise PolicyValidationError(
            '`remove-statements` may only be used in '
            'conjunction with `cross-account` filter on %s' % (self.manager.data,))

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('secretsmanager')
        for r in resources:
            try:
                self.process_resource(client, r)
            except Exception:
                self.log.exception("Error processing secretsmanager:%s", r['ARN'])

    def process_resource(self, client, resource):
        p = json.loads(resource.get('c7n:AccessPolicy'))
        if p is None:
            return

        statements, found = self.process_policy(
            p, resource, CrossAccountAccessFilter.annotation_key)

        if not found:
            return
        if statements:
            client.put_resource_policy(
                SecretId=resource['ARN'],
                ResourcePolicy=json.dumps(p)
            )
        else:
            client.delete_resource_policy(SecretId=resource['ARN'])


@SecretsManager.action_registry.register('set-encryption')
class SetEncryptionAction(Action):
    """
    Set kms encryption key for secrets, key supports ARN, ID, or alias

    :example:

    .. code-block:: yaml

        policies:
            - name: set-secret-encryption
              resource: aws.secrets-manager
              actions:
                - type: set-encryption
                  key: alias/foo/bar
    """

    schema = type_schema('set-encryption', key={'type': 'string'}, required=['key'])
    permissions = ('secretsmanager:UpdateSecret', )

    def process(self, resources):
        key = self.data['key']
        client = local_session(self.manager.session_factory).client('secretsmanager')
        for r in resources:
            client.update_secret(
                SecretId=r['Name'],
                KmsKeyId=key
            )

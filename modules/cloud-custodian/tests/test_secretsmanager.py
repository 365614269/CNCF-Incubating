# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import json
from .common import BaseTest
from c7n.exceptions import PolicyValidationError


class TestSecretsManager(BaseTest):

    def test_secrets_manager_cross_account(self):
        factory = self.replay_flight_data('test_secrets_manager_cross_account')
        p = self.load_policy({
            'name': 'secrets-manager',
            'resource': 'secrets-manager',
            'filters': ['cross-account']},
            session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
        secret = resources.pop()
        self.assertEqual(secret['Name'], 'c7n-test-key')
        self.assertEqual(
            secret['CrossAccountViolations'],
            [{'Action': 'secretsmanager:*',
              'Effect': 'Allow',
              'Principal': {'AWS': 'arn:aws:iam::123456789012:root'},
              'Resource': '*'}])

    def test_secrets_manager_kms_filter(self):
        session_factory = self.replay_flight_data('test_secrets_manager_kms_filter')
        kms = session_factory().client('kms')
        p = self.load_policy(
            {
                'name': 'test-secrets-manager-kms-filter',
                'resource': 'secrets-manager',
                'filters': [
                    {
                        'type': 'kms-key',
                        'key': 'c7n:AliasName',
                        'value': 'alias/skunk/trails'
                    }
                ]
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        aliases = kms.list_aliases(KeyId=resources[0]['KmsKeyId'])
        self.assertEqual(aliases['Aliases'][0]['AliasName'], 'alias/skunk/trails')

    def test_secrets_manager_has_statement_filter(self):
        factory = self.replay_flight_data('test_secrets_manager_has_statement_filter')
        p = self.load_policy({
            'name': 'secrets-manager-has-statement',
            'resource': 'secrets-manager',
            'filters': [{
                        "type": "has-statement",
                        "statements": [
                            {
                                "Effect": "Deny",
                                "Action": "secretsmanager:GetSecretValue"
                            }
                        ]
                        }]
        },
            session_factory=factory)
        resources = p.run()

        self.assertEqual(len(resources), 1)

    def test_secrets_manager_tag_resource(self):
        session = self.replay_flight_data("test_secrets_manager_tag")
        client = session(region="us-east-1").client("secretsmanager")
        p = self.load_policy(
            {
                "name": "secrets-manager-resource",
                "resource": "secrets-manager",
                "actions": [{"type": "tag", "key": "new-tag", "value": "new-value"}],
            },
            session_factory=session,
        )
        resources = p.run()
        self.assertFalse(resources[0].get('Tags'))

        p = self.load_policy(
            {
                "name": "secrets-manager-resource",
                "resource": "secrets-manager",
                "actions": [{"type": "remove-tag", "tags": ["new-tag"]}],
            },
            session_factory=session,
        )
        resources = p.run()
        self.assertEqual(resources[0]['Tags'][0]['Key'], 'new-tag')

        final_tags = client.describe_secret(SecretId="c7n-test-key").get("Tags")
        self.assertFalse(final_tags)

    def test_mark_secret_for_op(self):
        session = self.replay_flight_data("test_secrets_manager_mark_for_op")
        client = session(region="us-east-1").client("secretsmanager")
        p = self.load_policy(
            {
                "name": "secrets-manager-resource",
                "resource": "secrets-manager",
                "actions": [{"type": "mark-for-op", "op": "tag", "days": 1}],
            },
            session_factory=session,
        )
        resources = p.run()
        self.assertFalse(resources[0].get('Tags'))
        new_tags = client.describe_secret(SecretId="c7n-test-key").get("Tags")
        self.assertTrue("tag@" in new_tags[0].get("Value"))

    def test_secrets_manager_delete(self):
        session_factory = self.replay_flight_data('test_secrets_manager_delete')
        client = session_factory(region="us-east-1").client("secretsmanager")
        p = self.load_policy(
            {
                'name': 'secrets-manager-unencrypted-delete',
                'resource': 'secrets-manager',
                'filters': [
                    {
                        'type': 'value',
                        'key': 'Name',
                        'value': 'test'
                    }
                ],
                'actions': [
                    {
                        'type': 'delete',
                        'recovery_window': 7
                    }
                ]
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['Name'], 'test')
        self.assertEqual(len(resources[0].get('ReplicationStatus')), 2)
        secret_for_del = client.describe_secret(SecretId=resources[0]['ARN'])
        self.assertTrue('DeletedDate' in secret_for_del)

    def test_secrets_manager_set_key(self):
        session_factory = self.replay_flight_data('test_secrets_manager_set_encryption_key')
        client = session_factory().client('secretsmanager')
        p = self.load_policy(
            {
                'name': 'secrets-manager-set-key',
                'resource': 'aws.secrets-manager',
                'filters': [{'Name': 'ewerwrwe'}],
                'actions': [{'type': 'set-encryption', 'key': 'alias/qewrqwer'}]
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        response = client.describe_secret(SecretId=resources[0]['Name'])
        self.assertEqual(response['KmsKeyId'], 'alias/qewrqwer')

    def test_secretsmanager_remove_matched(self):
        session_factory = self.replay_flight_data("test_secretsmanager_remove_matched")
        resource_id = 'arn:aws:secretsmanager:us-east-1:644160558196:secret:test-ZO5wu6'
        client = session_factory().client("secretsmanager")
        client.put_resource_policy(SecretId=resource_id, ResourcePolicy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "SpecificAllow",
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::644160558196:user/Peter"
                        },
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": "*"
                    },
                    {
                        "Sid": "CrossAccount",
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::040813553448:user/pratyush"
                        },
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": "*"
                    }
                ]
            }))
        p = self.load_policy(
            {
                "name": "secrets-manager-rm-matched",
                "resource": "secrets-manager",
                "filters": [{"type": "cross-account"}],
                "actions": [{"type": "remove-statements", "statement_ids": "matched"}],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        data = client.get_resource_policy(SecretId=resource_id)
        access_policy = json.loads(data.get('ResourcePolicy'))
        self.assertEqual(len(access_policy.get('Statement')), 1)
        self.assertEqual([s['Sid'] for s in access_policy.get('Statement')], ["SpecificAllow"])

    def test_secretsmanager_remove_rbp(self):
        session_factory = self.replay_flight_data("test_secretsmanager_remove_rbp")
        resource_id = 'arn:aws:secretsmanager:us-east-1:644160558196:secret:test-ZO5wu6'
        client = session_factory().client("secretsmanager")
        client.put_resource_policy(SecretId=resource_id, ResourcePolicy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "CrossAccount",
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::040813553448:user/pratyush"
                        },
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": "*"
                    }
                ]
            }))
        p = self.load_policy(
            {
                "name": "secrets-manager-rm-rbp",
                "resource": "secrets-manager",
                "filters": [{"type": "cross-account"}],
                "actions": [{"type": "remove-statements", "statement_ids": "matched"}],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        data = client.get_resource_policy(SecretId=resource_id)
        self.assertEqual(data.get('ResourcePolicy'), None)

    def test_remove_statements_validation_error(self):
        self.assertRaises(
            PolicyValidationError,
            self.load_policy,
            {
                "name": "secrets-manager-remove-matched",
                "resource": "secrets-manager",
                "actions": [{"type": "remove-statements", "statement_ids": "matched"}],
            }
        )

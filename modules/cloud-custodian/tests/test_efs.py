# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from c7n.exceptions import PolicyValidationError

from .common import BaseTest, functional, event_data
from botocore.exceptions import ClientError

import uuid
import time

from operator import itemgetter
from c7n.testing import mock_datetime_now
from dateutil import parser
from pytest_terraform import terraform
import c7n.resources.efs
import c7n.filters.backup
import json
import pytest


class ElasticFileSystem(BaseTest):

    @functional
    def test_resource_manager(self):
        factory = self.replay_flight_data("test_efs_query")
        client = factory().client("efs")
        token = str(uuid.uuid4())
        fs_id = client.create_file_system(CreationToken=token).get("FileSystemId")
        self.addCleanup(client.delete_file_system, FileSystemId=fs_id)
        tags = [{"Key": "Name", "Value": "Somewhere"}]
        client.create_tags(FileSystemId=fs_id, Tags=tags)
        if self.recording:
            time.sleep(5)

        p = self.load_policy(
            {
                "name": "efs-query",
                "resource": "efs",
                "filters": [{"FileSystemId": fs_id}, {"tag:Name": "Somewhere"}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]["Tags"], tags)

    def test_mount_target_loading(self):
        factory = self.replay_flight_data("test_efs_subresource")
        p = self.load_policy(
            {"name": "test-mount-targets", "resource": "efs-mount-target"},
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 2)

    def test_mount_target_security_group(self):
        factory = self.replay_flight_data("test_efs_mount_secgroup")
        p = self.load_policy(
            {
                "name": "test-mount-secgroup",
                "resource": "efs-mount-target",
                "filters": [
                    {
                        "type": "security-group",
                        "key": "GroupId",
                        "value": "sg-ccf3a8a4",
                    },
                    # Use the same filter twice to excercise cache code
                    {
                        "type": "security-group",
                        "key": "GroupId",
                        "value": "sg-ccf3a8a4",
                    },
                ],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 3)
        resources = sorted(resources, key=itemgetter("MountTargetId"))
        self.assertEqual(resources[0]["MountTargetId"], "fsmt-a47385dd")

    def test_create_efs_mount_target(self):
        factory = self.replay_flight_data("test_create_efs_mount_target")
        policy = self.load_policy(
            {
                "name": "create-efs-mount-target",
                "resource": "efs-mount-target",
                "mode": {"type": "cloudtrail", "events": [{
                    "source": "elasticfilesystem.amazonaws.com",
                    "ids": "responseElements.mountTargetId",
                    "event": "CreateMountTarget"
                }]},
            },
            session_factory=factory,
        )

        event = {
            "detail": event_data("event-cloud-trail-create-efs-mount-target.json"),
            "debug": True,
        }
        resources = policy.push(event, None)
        self.assertEqual(len(resources), 1)

    def test_modify_efs_mount_target_security_group(self):
        factory = self.replay_flight_data("test_modify_efs_mount_target_security_group")
        policy = self.load_policy(
            {
                "name": "modify-efs-mount-target-security-group",
                "resource": "efs-mount-target",
                "mode": {"type": "cloudtrail", "events": [{
                    "source": "elasticfilesystem.amazonaws.com",
                    "ids": "requestParameters.mountTargetId",
                    "event": "ModifyMountTargetSecurityGroups"
                }]},
            },
            session_factory=factory,
        )

        event = {
            "detail": event_data("event-cloud-trail-update-efs-mount-target-security-group.json"),
            "debug": True,
        }
        resources = policy.push(event, None)
        self.assertEqual(len(resources), 1)

    def test_delete(self):
        factory = self.replay_flight_data("test_efs_delete")
        p = self.load_policy(
            {
                "name": "efs-query",
                "resource": "efs",
                "filters": [{"Name": "MyDocs"}],
                "actions": ["delete"],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]["Name"], "MyDocs")
        client = factory().client("efs")
        state = client.describe_file_systems().get("FileSystems", [])
        self.assertEqual(state, [])

    def test_kms_alias(self):
        factory = self.replay_flight_data("test_efs_kms_key_filter")
        p = self.load_policy(
            {
                "name": "efs-kms-alias",
                "resource": "efs",
                "filters": [
                    {
                        "type": "kms-key",
                        "key": "c7n:AliasName",
                        "value": "^(alias/aws/)",
                        "op": "regex"
                    }
                ]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(
            resources[0]['KmsKeyId'],
            'arn:aws:kms:us-east-1:644160558196:key/8785aeb9-a616-4e2b-bbd3-df3cde76bcc5') # NOQA

    def test_enable_lifecycle_policy(self):
        factory = self.replay_flight_data("test_enable_lifecycle_policy")
        client = factory().client("efs")
        res = client.describe_lifecycle_configuration(FileSystemId="fs-fac23c7a")
        self.assertEqual(res.get('LifecyclePolicies'), [])
        p = self.load_policy(
            {
                "name": "efs-lifecycle-policy",
                "resource": "efs",
                "filters": [{"Name": "c7n-test"}],
                "actions": [
                    {
                        "type": "configure-lifecycle-policy",
                        "state": "enable",
                        "rules": [{'TransitionToIA': 'AFTER_7_DAYS'}],
                    }
                ]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]["Name"], "c7n-test")
        self.assertEqual(resources[0]["FileSystemId"], "fs-fac23c7a")
        response = client.describe_lifecycle_configuration(FileSystemId="fs-fac23c7a")
        self.assertEqual(response.get('LifecyclePolicies'), [{'TransitionToIA': 'AFTER_7_DAYS'}])

    def test_disable_lifecycle_policy(self):
        factory = self.replay_flight_data("test_disable_lifecycle_policy")
        client = factory().client("efs")
        res = client.describe_lifecycle_configuration(FileSystemId="fs-fac23c7a")
        self.assertEqual(res.get('LifecyclePolicies'), [{'TransitionToIA': 'AFTER_7_DAYS'}])
        p = self.load_policy(
            {
                "name": "efs-lifecycle-policy-disable",
                "resource": "efs",
                "filters": [{"Name": "c7n-test"}],
                "actions": [
                    {
                        "type": "configure-lifecycle-policy",
                        "state": "disable",
                    }
                ]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]["Name"], "c7n-test")
        self.assertEqual(resources[0]["FileSystemId"], "fs-fac23c7a")
        response = client.describe_lifecycle_configuration(FileSystemId="fs-fac23c7a")
        self.assertEqual(response.get('LifecyclePolicies'), [])

    def test_lifecycle_policy_validation_error(self):
        self.assertRaises(
            PolicyValidationError,
            self.load_policy,
            {
                "name": "efs-lifecycle",
                "resource": "efs",
                "filters": [{"Name": "c7n-test"}],
                "actions": [{"type": "configure-lifecycle-policy", "state": "enable"}],
            }
        )

    def test_filter_lifecycle_policy_present(self):
        factory = self.replay_flight_data("test_filter_lifecycle_policy_present")
        p = self.load_policy(
            {
                "name": "efs-lifecycle-policy-enabled",
                "resource": "efs",
                "filters": [{"type": "lifecycle-policy",
                            "state": "present"}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]["FileSystemId"], "fs-5f61b0df")

    def test_filter_lifecycle_policy_absent(self):
        factory = self.replay_flight_data("test_filter_lifecycle_policy_absent")
        p = self.load_policy(
            {
                "name": "efs-lifecycle-policy-disabled",
                "resource": "efs",
                "filters": [{"type": "lifecycle-policy",
                            "state": "absent"}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]["FileSystemId"], "fs-a4cc1c24")

    def test_filter_lifecycle_policy_value(self):
        factory = self.replay_flight_data("test_filter_lifecycle_policy_value")
        p = self.load_policy(
            {
                "name": "efs-lifecycle-policy-enabled",
                "resource": "efs",
                "filters": [{"type": "lifecycle-policy",
                            "state": "present", "value": "AFTER_7_DAYS"}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]["FileSystemId"], "fs-5f61b0df")

    def test_filter_securetransport_check(self):
        factory = self.replay_flight_data("test_efs_filter_check_secure_transport")
        p = self.load_policy(
            {
                "name": "efs-check-securetransport",
                "resource": "efs",
                "filters": [{"type": "check-secure-transport"}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]["Name"], "efs-without-secure-transport")

    def test_efs_has_statement(self):
        factory = self.replay_flight_data("test_efs_has_statement")
        p = self.load_policy(
            {
                "name": "efs-has-statement",
                "resource": "efs",
                "filters": [
                    {
                        "type": "has-statement",
                        "statements": [
                            {
                                "Effect": "Allow",
                                "Condition":
                                    {"Bool": {"elasticfilesystem:AccessedViaMountTarget": "true"}},
                                "Resource": "{fs_arn}"
                            }
                        ]
                    }
                ],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]["Name"], "efs-has-statement")

        p = self.load_policy(
            {
                "name": "efs-has-statement",
                "resource": "efs",
                "filters": [
                    {
                        "type": "has-statement",
                        "statements": [
                            {
                                "Effect": "Deny"
                            }
                        ]
                    }
                ],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 0)

    def test_efs_consecutive_aws_backups_count_filter(self):
        session_factory = self.replay_flight_data("test_efs_consecutive_aws_backups_count_filter")
        p = self.load_policy(
            {
                "name": "efs_consecutive_aws_backups_count_filter",
                "resource": "efs",
                "filters": [
                    {
                        "type": "consecutive-aws-backups",
                        "count": 2,
                        "period": "days",
                        "status": "COMPLETED"
                    }
                ]
            },
            session_factory=session_factory,
        )
        with mock_datetime_now(parser.parse("2022-09-09T00:00:00+00:00"), c7n.filters.backup):
            resources = p.run()
        self.assertEqual(len(resources), 1)


@terraform('efs_remove_matched', teardown=terraform.TEARDOWN_IGNORE, scope='session')
def test_efs_remove_matched(test, efs_remove_matched):
    session_factory = test.replay_flight_data("test_efs_remove_matched")
    client = session_factory().client("efs")
    filesystem_id = efs_remove_matched['aws_efs_file_system.example.id']

    if test.recording:
        time.sleep(5)

    p = test.load_policy(
        {
            "name": "efs-rm-matched",
            "resource": "aws.efs",
            "filters": [
                {"FileSystemId": filesystem_id},
                {"type": "cross-account", "whitelist": ["185106417252"]},
            ],
            "actions": [{"type": "remove-statements", "statement_ids": "matched"}],
        },
        session_factory=session_factory,
    )
    resources = p.run()
    test.assertEqual([r["FileSystemId"] for r in resources], [filesystem_id])

    data = json.loads(
        client.describe_file_system_policy(FileSystemId=filesystem_id).get(
            "Policy"
        )
    )
    test.assertEqual(
        [s["Sid"] for s in data.get("Statement", ())], ["SpecificAllow"]
    )


@terraform('efs_remove_access_denied', teardown=terraform.TEARDOWN_IGNORE)
def test_efs_access_denied(test, efs_remove_access_denied):
    session_factory = test.replay_flight_data("test_efs_access_denied")
    client = session_factory().client("efs")
    filesystem_id = efs_remove_access_denied['aws_efs_file_system.example_test.id']

    if test.recording:
        time.sleep(10)

    p = test.load_policy(
        {
            "name": "efs-rm-named",
            "resource": "aws.efs",
            "filters": [{"FileSystemId": filesystem_id},
                        {"type": "cross-account", "whitelist": ["185106417252"]},]
        },
        session_factory=session_factory,
    )

    resources = p.run()
    test.assertEqual(len(resources), 0)

    with pytest.raises(ClientError) as e:
        client.describe_file_system_policy(FileSystemId=filesystem_id)

    test.assertTrue('AccessDeniedException' in str(e))


@terraform('efs_remove_matched', teardown=terraform.TEARDOWN_IGNORE, scope='session')
def test_efs_remove_named(test, efs_remove_matched):
    session_factory = test.replay_flight_data("test_efs_remove_named")
    filesystem_id = efs_remove_matched['aws_efs_file_system.example_client_error.id']

    if test.recording:
        time.sleep(5)

    p = test.load_policy(
        {
            "name": "efs-rm-named",
            "resource": "aws.efs",
            "filters": [{"FileSystemId": filesystem_id}],
            "actions": [
                {"type": "remove-statements", "statement_ids": ["WhatIsIt"]}
            ],
        },
        session_factory=session_factory,
    )

    resources = p.run()
    test.assertEqual(len(resources), 1)


@terraform('efs_remove_matched', teardown=terraform.TEARDOWN_IGNORE, scope='session')
def test_efs_client_error(test, efs_remove_matched):
    session_factory = test.replay_flight_data("test_efs_client_error")

    if test.recording:
        time.sleep(5)

    p = test.load_policy(
        {
            "name": "efs-rm-named",
            "resource": "aws.efs",
            "filters": [{"FileSystemId": "fs-095fec21dd6d065fb"}],
            "actions": [
                {"type": "remove-statements", "statement_ids": ["WhatIsIt"]}
            ],
        },
        session_factory=session_factory,
    )

    resources = p.run()
    test.assertEqual(len(resources), 1)


@terraform('efs_remove_matched', teardown=terraform.TEARDOWN_IGNORE, scope='session')
def test_efs_remove_statement(test, efs_remove_matched):
    session_factory = test.replay_flight_data("test_efs_remove_statement")
    client = session_factory().client("efs")
    filesystem_id = efs_remove_matched['aws_efs_file_system.example_remove_named.id']

    if test.recording:
        time.sleep(5)

    p = test.load_policy(
        {
            "name": "efs-rm-statement",
            "resource": "aws.efs",
            "filters": [{"FileSystemId": filesystem_id}],
            "actions": [
                {"type": "remove-statements", "statement_ids": ["RemoveMe"]}
            ],
        },
        session_factory=session_factory,
    )
    resources = p.run()
    test.assertEqual(len(resources), 1)
    data = json.loads(
        client.describe_file_system_policy(FileSystemId=filesystem_id).get(
            "Policy"
        )
    )
    test.assertTrue("RemoveMe" not in [s["Sid"] for s in data.get("Statement", ())])

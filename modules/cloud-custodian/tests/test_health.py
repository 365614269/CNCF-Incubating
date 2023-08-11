# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from .common import BaseTest


class HealthResource(BaseTest):

    def test_health_query(self):
        session_factory = self.replay_flight_data("test_health_query")
        p = self.load_policy(
            {"name": "account-health-query", "resource": "health-event"},
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 0)

    def test_health_resource_query(self):
        session_factory = self.replay_flight_data("test_health_resource_query")
        p = self.load_policy(
            {
                "name": "account-health-ec2-query",
                "resource": "health-event",
                "query": [{"services": "EC2"}],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]["service"], "EC2")

    def test_health_augment(self):
        session_factory = self.replay_flight_data("test_health_augment")
        p = self.load_policy(
            {
                "name": "account-health-augment",
                "resource": "health-event",
                "query": [{"services": ["BILLING", "IAM"]}],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        for r in resources:
            self.assertTrue("Description" in r)
            self.assertTrue(
                (r["eventTypeCategory"] == "accountNotification") ^ ("AffectedEntities" in r)
            )

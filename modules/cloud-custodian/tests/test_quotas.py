# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
#

from c7n.executor import MainThreadExecutor
from c7n.resources.quotas import ServiceQuota
from c7n.utils import local_session

from .common import BaseTest


class TestQuotas(BaseTest):

    def setUp(self):
        super().setUp()
        self.patch(ServiceQuota, "executor_factory", MainThreadExecutor)

    def test_service_quota_request_history_filter(self):
        session_factory = self.replay_flight_data('test_service_quota')

        p = self.load_policy({
            "name": "service-quota-history-filter",
            "resource": "aws.service-quota",
            "filters": [{
                "type": "request-history",
                "key": "[].Status",
                "value": "CASE_CLOSED",
                "op": "in",
                "value_type": "swap"}
            ]},
            session_factory=session_factory
        )
        resources = p.run()
        self.assertTrue(resources)

    def test_service_quota_request_increase(self):
        session_factory = self.replay_flight_data('test_service_quota')
        p = self.load_policy({
            "name": "service-quota-request-increase",
            "resource": "aws.service-quota",
            "filters": [{
                "QuotaCode": "L-355B2B67"}],
            "actions": [{
                "type": "request-increase",
                "multiplier": 1.2}
            ]},
            session_factory=session_factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
        client = local_session(session_factory).client('service-quotas')
        changes = client.list_requested_service_quota_change_history_by_quota(
            ServiceCode=resources[0]['ServiceCode'],
            QuotaCode=resources[0]['QuotaCode']
        )['RequestedQuotas']
        self.assertTrue(changes)

    # Given the ServiceQuota.augment.get_quotas is a nested function,can't patch it;
    # This test case is the best we can do at the moment.
    def test_service_quota_metadata_incl_filter(self):
        session_factory = self.replay_flight_data('test_service_quota')
        p = self.load_policy({
            "name": "service-quota-metaddata-filter",
            "resource": "aws.service-quota",
            "query": [{"include_service_codes": ["ec2"]}],
            },
            session_factory=session_factory)
        resources = p.run()
        # called ListAWSDefaultServiceQuotas once, 6 quotas returned
        # called servicequotas.ListServiceQuotas once, 2 quotas returned
        assert len(resources) == 8

    def test_service_quota_metadata_excl_filter(self):
        session_factory = self.replay_flight_data('test_service_quota')
        p = self.load_policy({
            "name": "service-quota-metaddata-filter",
            "resource": "aws.service-quota",
            "query": [{"exclude_service_codes": ["logs"]}],
            },
            session_factory=session_factory)
        resources = p.run()
        # called ListAWSDefaultServiceQuotas twice, 6x2 quotas returned
        # called servicequotas.ListServiceQuotas twice, 2+1 quotas returned
        assert len(resources) == 15

    def test_usage_metric_filter(self):
        session_factory = self.replay_flight_data('test_service_quota')
        p = self.load_policy({
            "name": "service-quota-usage-metric",
            "resource": "aws.service-quota",
            "filters": [
                {"UsageMetric": "present"},
                {"type": "usage-metric",
                 "min_period": 60,
                 "limit": 20}
            ]},
            session_factory=session_factory)
        resources = p.run()
        self.assertEqual(len(resources), 2)

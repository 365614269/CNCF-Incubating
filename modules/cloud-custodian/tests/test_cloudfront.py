# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from .common import BaseTest, event_data
from c7n.resources.aws import shape_validate
from c7n.utils import local_session, jmespath_compile
from unittest.mock import MagicMock


class CloudFrontWaf(BaseTest):

    def test_waf(self):
        factory = self.replay_flight_data("test_distribution_waf")
        p = self.load_policy(
            {
                "name": "waf-cfront",
                "resource": "distribution",
                "filters": [{"type": "waf-enabled", "state": False}],
                "actions": [{"type": "set-waf", "web-acl": "test", "state": True}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 2)

        p = self.load_policy(
            {
                "name": "waf-cfront",
                "resource": "distribution",
                "filters": [{"type": "waf-enabled", "web-acl": "test", "state": False}],
                "actions": [{"type": "set-waf", "web-acl": "test", "state": True}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 0)

        p = self.load_policy(
            {
                "name": "waf-cfront",
                "resource": "distribution",
                "filters": [{"type": "waf-enabled", "web-acl": "test", "state": False}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 2)

    def test_waf_to_wafv2(self):
        factory = self.replay_flight_data("test_distribution_waf")
        p = self.load_policy(
            {
                "name": "waf-cfront",
                "resource": "distribution",
                "filters": [{"type": "waf-enabled", "state": False}],
                "actions": [{"type": "set-wafv2", "web-acl": "testv2", "state": True}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 2)

        p = self.load_policy(
            {
                "name": "waf-cfront",
                "resource": "distribution",
                "filters": [{"type": "waf-enabled", "web-acl": "test", "state": False}],
                "actions": [{"type": "set-wafv2", "web-acl": "testv2", "state": True}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 0)

        p = self.load_policy(
            {
                "name": "waf-cfront",
                "resource": "distribution",
                "filters": [{"type": "waf-enabled", "web-acl": "test", "state": False}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 2)

    def test_set_wafv2_active_response(self):
        factory = self.replay_flight_data("test_distribution_wafv2")
        policy = self.load_policy(
            {
                "name": "waf-cloudfront-active-response",
                "resource": "distribution",
                "mode": {"type": "cloudtrail", "events": [{
                    "source": "cloudfront.amazonaws.com",
                    "ids": "responseElements.distribution.id",
                    "event": "CreateDistribution"
                }]},
                "filters": [{"type": "wafv2-enabled", "state": False}],
                "actions": [{"type": "set-wafv2", "state": True,
                             "force": True, "web-acl": "testv2"}],
            },
            session_factory=factory,
        )

        resources = policy.push(event_data("event-cloud-trail-create-distribution.json"))
        self.assertEqual(len(resources), 1)

    def test_set_wafv2_filter_regex(self):
        factory = self.replay_flight_data("test_distribution_wafv2_regex")

        policy = self.load_policy(
            {
                "name": "waf-cloudfront-update-response",
                "resource": "distribution",
                "mode": {"type": "cloudtrail", "events": [{
                    "source": "cloudfront.amazonaws.com",
                    "ids": "requestParameters.id",
                    "event": "UpdateDistribution"
                }]},
                "filters": [{"type": "wafv2-enabled", "state": True}],
            },
            session_factory=factory,
        )
        resources = policy.push(event_data("event-cloud-trail-update-distribution.json"))
        self.assertEqual(len(resources), 1)

        policy = self.load_policy(
            {
                "name": "waf-cloudfront-update-response",
                "resource": "distribution",
                "mode": {"type": "cloudtrail", "events": [{
                    "source": "cloudfront.amazonaws.com",
                    "ids": "requestParameters.id",
                    "event": "UpdateDistribution"
                }]},
                "filters": [{"type": "wafv2-enabled",
                             "web-acl": "FMManagedWebACLV2-FMS-.*",
                             "state": True}],
            },
            session_factory=factory,
        )
        resources = policy.push(event_data("event-cloud-trail-update-distribution.json"))
        self.assertEqual(len(resources), 1)

        policy = self.load_policy(
            {
                "name": "waf-cloudfront-update-response",
                "resource": "distribution",
                "mode": {"type": "cloudtrail", "events": [{
                    "source": "cloudfront.amazonaws.com",
                    "ids": "requestParameters.id",
                    "event": "UpdateDistribution"
                }]},
                "filters": [{"type": "wafv2-enabled",
                             "web-acl": "FMManagedWebACLV2-FMS-.*",
                             "state": True}],
                "actions": [{"type": "set-wafv2", "state": True,
                             "force": True, "web-acl": "FMManagedWebACLV2-FMS-T.*"}],
            },
            session_factory=factory,
        )
        resources = policy.push(event_data("event-cloud-trail-update-distribution.json"))
        self.assertEqual(len(resources), 1)

    def test_set_wafv2_action_regex_multiple_webacl_match(self):
        factory = self.replay_flight_data("test_distribution_wafv2_regex_multiple_webacl_match")

        policy = self.load_policy(
            {
                "name": "waf-cloudfront-update-response",
                "resource": "distribution",
                "mode": {"type": "cloudtrail", "events": [{
                    "source": "cloudfront.amazonaws.com",
                    "ids": "requestParameters.id",
                    "event": "UpdateDistribution"
                }]},
                "filters": [{"type": "wafv2-enabled",
                             "web-acl": "testv2",
                             "state": False}],
                "actions": [{"type": "set-wafv2", "state": True, "force": True,
                             "web-acl": "FMManagedWebACLV2-FMS-T.*"}],
            },
            session_factory=factory,
        )
        resources = policy.push(event_data("event-cloud-trail-tag-distribution.json"))
        self.assertEqual(len(resources), 0)

    def test_set_wafv2_active_response_tag_resource(self):
        factory = self.replay_flight_data("test_distribution_wafv2")
        policy = self.load_policy(
            {
                "name": "waf-cloudfront-active-response",
                "resource": "distribution",
                "mode": {"type": "cloudtrail", "events": [{
                    "source": "cloudfront.amazonaws.com",
                    "ids": "requestParameters.resource",
                    "event": "TagResource"
                }]},
                "filters": [{"type": "wafv2-enabled", "state": False}],
                "actions": [{"type": "set-wafv2", "state": True,
                             "force": True, "web-acl": "testv2"}],
            },
            session_factory=factory,
        )

        resources = policy.push(event_data("event-cloud-trail-tag-distribution.json"))
        self.assertEqual(len(resources), 1)


class CloudFront(BaseTest):

    def test_shield_metric_filter(self):
        factory = self.replay_flight_data("test_distribution_shield_metrics")
        p = self.load_policy(
            {
                "name": "ddos-filter",
                "resource": "distribution",
                "filters": [
                    {
                        "type": "shield-metrics",
                        "name": "DDoSDetected",
                        "value": 1,
                        "op": "ge",
                    }
                ],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 0)

    def test_distribution_metric_filter(self):
        factory = self.replay_flight_data("test_distribution_metric_filter")
        p = self.load_policy(
            {
                "name": "requests-filter",
                "resource": "distribution",
                "filters": [
                    {"type": "metrics", "name": "Requests", "value": 3, "op": "ge"}
                ],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(resources[0]["DomainName"], "d32plmcrnvwzrd.cloudfront.net")

    def test_distribution_set_ssl(self):
        factory = self.replay_flight_data("test_distrbution_set_ssl")

        k = "DefaultCacheBehavior.ViewerProtocolPolicy"

        p = self.load_policy(
            {
                "name": "distribution-set-ssl",
                "resource": "distribution",
                "filters": [
                    {"type": "value", "key": k, "value": "allow-all", "op": "contains"}
                ],
                "actions": [
                    {"type": "set-protocols", "ViewerProtocolPolicy": "https-only"}
                ],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        expr = jmespath_compile(k)
        r = expr.search(resources[0])
        self.assertTrue("allow-all" in r)

        client = local_session(factory).client("cloudfront")
        resp = client.list_distributions()
        self.assertEqual(
            resp["DistributionList"]["Items"][0]["DefaultCacheBehavior"][
                "ViewerProtocolPolicy"
            ],
            "https-only",
        )

    def test_distribution_custom_origin(self):
        factory = self.replay_flight_data("test_distrbution_custom_origin")

        k = "Origins.Items[].CustomOriginConfig.OriginSslProtocols.Items[]"

        p = self.load_policy(
            {
                "name": "distribution-set-ssl",
                "resource": "distribution",
                "filters": [
                    {"type": "value", "key": k, "value": "TLSv1", "op": "contains"}
                ],
                "actions": [
                    {
                        "type": "set-protocols",
                        "OriginSslProtocols": ["TLSv1.1", "TLSv1.2"],
                        "OriginProtocolPolicy": "https-only",
                    }
                ],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        expr = jmespath_compile(k)
        r = expr.search(resources[0])
        self.assertTrue("TLSv1" in r)

        client = local_session(factory).client("cloudfront")
        resp = client.list_distributions()
        self.assertEqual(
            resp["DistributionList"]["Items"][0]["Origins"]["Items"][0][
                "CustomOriginConfig"
            ][
                "OriginProtocolPolicy"
            ],
            "https-only",
        )
        self.assertTrue(
            "TLSv1.2" in resp["DistributionList"]["Items"][0]["Origins"]["Items"][0][
                "CustomOriginConfig"
            ][
                "OriginSslProtocols"
            ][
                "Items"
            ]
        )
        self.assertFalse(
            "TLSv1" in resp["DistributionList"]["Items"][0]["Origins"]["Items"][0][
                "CustomOriginConfig"
            ][
                "OriginSslProtocols"
            ][
                "Items"
            ]
        )

    def test_distribution_disable(self):
        factory = self.replay_flight_data("test_distrbution_disable")

        p = self.load_policy(
            {
                "name": "distribution-disable",
                "resource": "distribution",
                "filters": [
                    {
                        "type": "value",
                        "key": "DefaultCacheBehavior.ViewerProtocolPolicy",
                        "value": "allow-all",
                        "op": "contains",
                    }
                ],
                "actions": [{"type": "disable"}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]["Enabled"], True)

        client = local_session(factory).client("cloudfront")
        resp = client.list_distributions()
        self.assertEqual(resp["DistributionList"]["Items"][0]["Enabled"], False)

    def test_distribution_check_s3_origin_missing_bucket(self):
        factory = self.replay_flight_data("test_distribution_check_s3_origin_missing_bucket")

        p = self.load_policy(
            {
                "name": "test_distribution_check_s3_origin_missing_bucket",
                "resource": "distribution",
                "filters": [
                    {
                        "type": "mismatch-s3-origin",
                    }
                ]
            },
            session_factory=factory,
        )

        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['c7n:mismatched-s3-origin'][0], 'c7n-idontexist')

    def test_distribution_check_s3_origin_missing_bucket_region(self):
        factory = self.replay_flight_data("test_distribution_check_s3_origin_missing_bucket_region")

        p = self.load_policy(
            {
                "name": "test_distribution_check_s3_origin_missing_bucket",
                "resource": "distribution",
                "filters": [
                    {
                        "type": "mismatch-s3-origin",
                    }
                ]
            },
            session_factory=factory,
        )

        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['c7n:mismatched-s3-origin'][0], 'c7n-test-bucket')

    def test_distribution_check_logging_enabled(self):
        factory = self.replay_flight_data("test_distribution_check_logging_enabled")

        p = self.load_policy(
            {
                "name": "test_distribution_logging_enabled",
                "resource": "distribution",
                "filters": [
                    {
                        "type": "distribution-config",
                        "key": "Logging.Enabled",
                        "value": True
                    }
                ]
            },
            session_factory=factory,
        )

        resources = p.run()

        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['c7n:distribution-config']['Logging']['Enabled'], True)

    def test_distribution_check_logging_enabled_error(self):
        factory = self.replay_flight_data("test_distribution_check_logging_enabled")

        client = factory().client("cloudfront")
        mock_factory = MagicMock()
        mock_factory.region = 'us-east-1'
        mock_factory().client(
            'cloudfront').exceptions.NoSuchDistribution = (
                client.exceptions.NoSuchDistribution)

        mock_factory().client('cloudfront').get_distribution_config.side_effect = (
            client.exceptions.NoSuchDistribution(
                {'Error': {'Code': 'xyz'}},
                operation_name='get_distribution_config'))
        p = self.load_policy(
            {
                "name": "test_distribution_logging_enabled",
                "resource": "distribution",
                "filters": [
                    {
                        "type": "distribution-config",
                        "key": "Logging.Enabled",
                        "value": True
                    }
                ]
            },
            session_factory=mock_factory,
        )

        try:
            p.resource_manager.filters[0].process(
                [{'Id': 'abc'}])
        except client.exceptions.NoSuchDistribution:
            self.fail('should not raise')
        mock_factory().client('cloudfront').get_distribution_config.assert_called_once()

    def test_streaming_distribution_check_logging_enabled(self):
        factory = self.replay_flight_data("test_streaming_distribution_check_logging_enabled")

        p = self.load_policy(
            {
                "name": "test_streaming_distribution_logging_enabled",
                "resource": "streaming-distribution",
                "filters": [
                    {
                        "type": "distribution-config",
                        "key": "Logging.Enabled",
                        "value": True
                    }
                ]
            },
            session_factory=factory,
        )

        resources = p.run()

        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['c7n:distribution-config']['Logging']['Enabled'],
            True)

    def test_streaming_distribution_check_logging_enabled_error(self):
        factory = self.replay_flight_data("test_streaming_distribution_check_logging_enabled")

        client = factory().client("cloudfront")
        mock_factory = MagicMock()
        mock_factory.region = 'us-east-1'
        mock_factory().client(
            'cloudfront').exceptions.NoSuchStreamingDistribution = (
                client.exceptions.NoSuchStreamingDistribution)

        mock_factory().client('cloudfront').get_streaming_distribution_config.side_effect = (
            client.exceptions.NoSuchStreamingDistribution(
                {'Error': {'Code': 'xyz'}},
                operation_name='get_streaming_distribution_config'))
        p = self.load_policy(
            {
                "name": "test_streaming_distribution_logging_enabled",
                "resource": "streaming-distribution",
                "filters": [
                    {
                        "type": "distribution-config",
                        "key": "Logging.Enabled",
                        "value": True
                    }
                ]
            },
            session_factory=mock_factory,
        )

        try:
            p.resource_manager.filters[0].process(
                [{'Id': 'abc'}])
        except client.exceptions.NoSuchDistribution:
            self.fail('should not raise')
        mock_factory().client('cloudfront').get_streaming_distribution_config.assert_called_once()

    def test_distribution_tag(self):
        factory = self.replay_flight_data("test_distrbution_tag")

        p = self.load_policy(
            {
                "name": "distribution-tag",
                "resource": "distribution",
                "filters": [{"tag:abc": "present"}],
                "actions": [{"type": "tag", "key": "123", "value": "456"}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

        client = local_session(factory).client("cloudfront")
        resp = client.list_tags_for_resource(Resource=resources[0]["ARN"])
        self.assertEqual(len(resp["Tags"]["Items"]), 2)

    def test_streaming_distribution_disable(self):
        factory = self.replay_flight_data("test_streaming_distrbution_disable")

        p = self.load_policy(
            {
                "name": "streaming-distribution-disable",
                "resource": "streaming-distribution",
                "filters": [
                    {
                        "type": "value",
                        "key": "S3Origin.OriginAccessIdentity",
                        "value": "",
                    }
                ],
                "actions": [{"type": "disable"}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]["Enabled"], True)

        client = local_session(factory).client("cloudfront")
        resp = client.list_streaming_distributions()
        self.assertEqual(
            resp["StreamingDistributionList"]["Items"][0]["Enabled"], False
        )

    def test_streaming_distribution_tag(self):
        factory = self.replay_flight_data("test_streaming_distrbution_tag")

        p = self.load_policy(
            {
                "name": "streaming-distribution-tag",
                "resource": "streaming-distribution",
                "filters": [{"tag:123": "present"}],
                "actions": [{"type": "tag", "key": "abc", "value": "123"}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

        client = local_session(factory).client("cloudfront")
        resp = client.list_tags_for_resource(Resource=resources[0]["ARN"])
        self.assertEqual(len(resp["Tags"]["Items"]), 2)

    def test_cloudfront_tagging_multi_region(self):
        factory = self.replay_flight_data("test_cloudfront_multi_region")
        east_p = self.load_policy(
            {
                "name": "cloudfront-tagging-us-east-1",
                "resource": "distribution",
                "filters": [{"tag:tag": "present"}]
            },
            config=dict(region='us-east-1'),
            session_factory=factory,
        )

        west_p = self.load_policy(
            {
                "name": "cloudfront-tagging-us-west-2",
                "resource": "distribution",
                "filters": [{"tag:tag": "present"}]
            },
            config=dict(region='us-west-2'),
            session_factory=factory,
        )

        east_resources = east_p.run()
        west_resources = west_p.run()

        self.assertEqual(east_resources, west_resources)

    def test_cloudfront_update_deep_attribute(self):
        factory = self.replay_flight_data(
            "test_distribution_update_deep_attribute",
            region="us-east-2")
        p = self.load_policy(
            {
                "name": "cloudfront-update-tls",
                "resource": "distribution",
                "filters": [
                    {
                        "DomainName": "dal78uzs60406.cloudfront.net",
                    },
                    {
                        "type": "distribution-config",
                        "key": "ViewerCertificate.MinimumProtocolVersion",
                        "op": "in",
                        "value": ["TLSv1.1_2016", "TLSv1_2016", "TLSv1", "SSLv3"],
                    },
                    {
                        "type": "distribution-config",
                        "key": "ViewerCertificate.CertificateSource",
                        "op": "in",
                        "value": ["acm", "iam"],
                    },
                ],
                "actions": [
                    {
                        "type": "set-attributes",
                        "attributes": {
                            "ViewerCertificate": {
                                "MinimumProtocolVersion": "TLSv1.2_2018",
                            }
                        },
                    },
                ],
            },
            config=dict(region='us-east-2'),
            session_factory=factory,
        )

        resources = p.run()

        self.assertEqual(len(resources), 1)

        client = local_session(factory).client("cloudfront")
        dist_id = resources[0]['Id']
        resp = client.get_distribution_config(Id=dist_id)

        # Check attribute updated by policy action
        self.assertEqual(
            resp['DistributionConfig']['ViewerCertificate']['MinimumProtocolVersion'],
            'TLSv1.2_2018'
        )

        # Check deep attribute from original configuration
        self.assertEqual(
            resp['DistributionConfig']['ViewerCertificate']['CertificateSource'],
            'acm'
        )

    def test_cloudfront_update_distribution(self):
        factory = self.replay_flight_data("test_distribution_update_distribution")
        p = self.load_policy(
            {
                "name": "cloudfront-tagging-us-east-1",
                "resource": "distribution",
                "filters": [
                    {
                        "type": "distribution-config",
                        "key": "Logging.Enabled",
                        "value": False,
                    }
                ],
                "actions": [
                    {
                        "type": "set-attributes",
                        "attributes": {
                            "Comment": "",
                            "Enabled": True,
                            "Logging": {
                                "Enabled": True,
                                "IncludeCookies": False,
                                "Bucket": 'test-logging.s3.amazonaws.com',
                                "Prefix": '',
                            }
                        }
                    }
                ],
            },
            config=dict(region='us-east-1'),
            session_factory=factory,
        )

        resources = p.run()

        self.assertEqual(len(resources), 1)

        client = local_session(factory).client("cloudfront")
        dist_id = resources[0]['Id']
        resp = client.get_distribution_config(Id=dist_id)
        self.assertEqual(
            resp['DistributionConfig']['Logging']['Enabled'], True
        )

    def test_cloudfront_update_streaming_distribution(self):
        factory = self.replay_flight_data("test_distribution_update_streaming_distribution")
        p = self.load_policy(
            {
                "name": "cloudfront-tagging-us-east-1",
                "resource": "streaming-distribution",
                "filters": [
                    {
                        "type": "distribution-config",
                        "key": "Logging.Enabled",
                        "value": False,
                    }
                ],
                "actions": [
                    {
                        "type": "set-attributes",
                        "attributes": {
                            "Logging": {
                                "Enabled": True,
                                "Bucket": 'test-streaming-distribution-logging.s3.amazonaws.com',
                                "Prefix": '',
                            }
                        }
                    }
                ],
            },
            config=dict(region='us-east-1'),
            session_factory=factory,
        )

        resources = p.run()

        self.assertEqual(len(resources), 1)

        client = local_session(factory).client("cloudfront")
        dist_id = resources[0]['Id']
        resp = client.get_streaming_distribution_config(Id=dist_id)
        self.assertEqual(
            resp['StreamingDistributionConfig']['Logging']['Enabled'], True
        )

    def test_cloudfront_post_finding(self):
        factory = self.replay_flight_data(
            "test_distribution_post_finding",
            region="us-east-2")
        p = self.load_policy(
            {
                "name": "cloudfront-post-finding",
                "resource": "distribution",
                "filters": [
                    {
                        "DomainName": "dal78uzs60406.cloudfront.net",
                    },
                    {
                        "type": "distribution-config",
                        "key": "ViewerCertificate.MinimumProtocolVersion",
                        "op": "in",
                        "value": ["TLSv1.1_2016", "TLSv1_2016", "TLSv1", "SSLv3"],
                    },
                ],
                "actions": [
                    {
                        "type": "post-finding",
                        "compliance_status": "FAILED",
                        "description": "Deprecated TLS version support",
                        "types": [
                            "Software and Configuration Checks/AWS Security Best Practices"
                        ],
                    },
                ],
            },
            config={'region': 'us-east-2'},
            session_factory=factory,
        )

        resources = p.resource_manager.resources()
        self.assertEqual(len(resources), 1)
        formatted_resource = p.resource_manager.actions[0].format_resource(resources[0])
        shape_validate(
            formatted_resource['Details']['AwsCloudFrontDistribution'],
            'AwsCloudFrontDistributionDetails',
            'securityhub')


class CloudFrontWafV2(BaseTest):

    def test_wafv2(self):
        factory = self.replay_flight_data("test_distribution_wafv2")
        p = self.load_policy(
            {
                "name": "wafv2-cfront",
                "resource": "distribution",
                "filters": [{"type": "wafv2-enabled", "state": False}]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 2)

        p = self.load_policy(
            {
                "name": "wafv2-cfront",
                "resource": "distribution",
                "filters": [{"type": "wafv2-enabled", "web-acl": "testv2", "state": False}],
                "actions": [{"type": "set-wafv2", "web-acl": "testv2", "state": True}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 2)

        p = self.load_policy(
            {
                "name": "wafv2-cfront",
                "resource": "distribution",
                "filters": [{"type": "wafv2-enabled", "web-acl": "testv2", "state": False}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 2)

    def test_wafv2_to_waf(self):
        factory = self.replay_flight_data("test_distribution_wafv2")
        p = self.load_policy(
            {
                "name": "wafv2-cfront",
                "resource": "distribution",
                "filters": [{"type": "wafv2-enabled", "state": False}],
                "actions": [{"type": "set-waf", "web-acl": "test", "state": True, "force": True}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 2)

        p = self.load_policy(
            {
                "name": "wafv2-cfront",
                "resource": "distribution",
                "filters": [{"type": "wafv2-enabled", "web-acl": "testv2", "state": False}],
                "actions": [{"type": "set-waf", "web-acl": "test", "state": True, "force": True}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 2)

        p = self.load_policy(
            {
                "name": "wafv2-cfront",
                "resource": "distribution",
                "filters": [{"type": "wafv2-enabled", "web-acl": "test", "state": False}],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 2)

    def test_wafv2_value(self):
        factory = self.replay_flight_data("test_distribution_wafv2_value")
        p = self.load_policy(
            {
                "name": "wafv2-value-cfront",
                "resource": "distribution",
                "filters": [{
                    "type": "wafv2-enabled",
                    "key": "length(Rules)",
                    "op": "gte",
                    "value": 1
                }]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

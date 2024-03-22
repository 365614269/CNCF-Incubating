# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from c7n.reports.csvout import Formatter
from c7n.resources.appmesh import AppmeshMesh, AppmeshVirtualGateway
from .apicallcaptor import ApiCallCaptor
from .common import BaseTest, event_data


# during recording create some sample resources in AWS then
# set use a flight recorder and set the config region to wherever you want to read state from.
# this will create recording files in the placebo dir.
# session_factory = self.record_flight_data('test_appmesh_virtualgateway')
# config = Config.empty(region="eu-west-2")

# File names in the placebo directory follow the pattern <servicename>.<OperationName>_<call#>.json
# So boto3 "AppMesh.Client.describe_mesh()" becomes "appmesh.DescribeMesh"
# and the _<call#> suffix corresponds with the file to load for each call to that api.


class TestAppmeshMesh(BaseTest):
    def test_appmesh(self):
        session_factory = self.replay_flight_data('test_appmesh_mesh')

        # test tags are populated and also the "spec" section

        p = self.load_policy(
            {
                "name": "appmesh-mesh-policy",
                "resource": "aws.appmesh-mesh",
                'filters': [
                    # only one resource should meet both conditions.
                    {"and": [
                        {"or": [
                            {'tag:MyTagName': 'm1'},
                            {'tag:MyTagName': 'm2'}
                        ]},
                        {
                            "type": "value",
                            "key": "spec.egressFilter.type",
                            "op": "eq",
                            "value": "DROP_ALL"
                        }
                    ]}
                ],
            },
            session_factory=session_factory,
        )

        captor = ApiCallCaptor.start_capture()
        # RUN THE SUT
        resources = p.run()

        self.assertEqual(
            [{'Tags': [{'Key': 'MyTagName', 'Value': 'm2'}],
              'arn': 'arn:aws:appmesh:eu-west-2:123456789012:mesh/m2',
              'c7n:MatchedFilters': ['tag:MyTagName', 'spec.egressFilter.type'],
              'createdAt': '2023-11-03T02:36:27.877000+00:00',
              'lastUpdatedAt': '2023-11-03T02:36:27.877000+00:00',
              'meshName': 'm2',
              'meshOwner': '123456789012',
              'metadata': {'arn': 'arn:aws:appmesh:eu-west-2:123456789012:mesh/m2',
                           'createdAt': '2023-11-03T02:36:27.877000+00:00',
                           'lastUpdatedAt': '2023-11-03T02:36:27.877000+00:00',
                           'meshOwner': '123456789012',
                           'resourceOwner': '123456789012',
                           'uid': '1013368a-8d58-4b30-b08e-67347af88525',
                           'version': 1},
              'resourceOwner': '123456789012',
              'spec': {'egressFilter': {'type': 'DROP_ALL'},
                       'serviceDiscovery': {'ipPreference': 'IPv6_PREFERRED'}},
              'status': {'status': 'ACTIVE'},
              'version': 1},
             ],
            resources,
        )

        # These assertions are necessary to be sure that the "get_arns" function is correctly
        # deriving the ARN.
        # See the documentation on the "arn" field in appmesh.py.
        arns = p.resource_manager.get_arns(resources)
        self.assertEqual(
            [
                'arn:aws:appmesh:eu-west-2:123456789012:mesh/m2',
            ],
            arns,
        )

        # The "placebo" testing library doesn't allow us to make assertions
        # linking specific api's calls to the specific mock response file
        # that will serve that request. So we will compensate here by
        # making an assertion about all the api calls and the order
        # of calls that must be made.
        self.assertEqual(
            [
                {'operation': 'ListMeshes', 'params': {}, 'service': 'appmesh'},
                {'operation': 'DescribeMesh', 'params': {'meshName': 'm1'}, 'service': 'appmesh'},
                {'operation': 'DescribeMesh', 'params': {'meshName': 'm2'}, 'service': 'appmesh'},
                {'operation': 'DescribeMesh', 'params': {'meshName': 'm3'}, 'service': 'appmesh'},
                {
                    'operation': 'GetResources',
                    'params': {
                        'ResourceARNList': [
                            'arn:aws:appmesh:eu-west-2:123456789012:mesh/m1',
                            'arn:aws:appmesh:eu-west-2:123456789012:mesh/m2',
                            'arn:aws:appmesh:eu-west-2:123456789012:mesh/m3',
                        ]
                    },
                    'service': 'resourcegroupstaggingapi',
                },
            ],
            captor.calls,
        )

    def test_appmesh_event(self):
        session_factory = self.replay_flight_data('test_appmesh_mesh_event')
        p = self.load_policy(
            {
                "name": "appmesh-mesh-policy",
                "resource": "aws.appmesh-mesh",
                "mode": {
                    "type": "cloudtrail",
                    "role": "CloudCustodian",
                    "events": [
                        {
                            "source": "appmesh.amazonaws.com",
                            "event": "CreateMesh",
                            "ids": "requestParameters.meshName",
                        }
                    ],
                },
            },
            session_factory=session_factory,
        )

        # event_data() names a file in tests/data/cwe that will drive the test execution.
        # file contains an event matching that which AWS would generate in cloud trail.
        event = {
            "detail": event_data("event-appmesh-create-mesh.json"),
            "debug": True,
        }

        captor = ApiCallCaptor.start_capture()

        # RUN THE SUT
        resources = p.push(event, None)
        resources.sort(key=lambda r: r["arn"])

        self.assertEqual(
            [
                {
                    'Tags': [{'Key': 'MyTagName', 'Value': 'm1'}],
                    'arn': 'arn:aws:appmesh:eu-west-2:123456789012:mesh/m1',
                    'createdAt': '2023-11-03T02:36:27.877000+00:00',
                    'lastUpdatedAt': '2023-11-03T02:36:27.877000+00:00',
                    'meshName': 'm1',
                    'meshOwner': '123456789012',
                    'metadata': {'arn': 'arn:aws:appmesh:eu-west-2:123456789012:mesh/m1',
                                 'createdAt': '2023-11-03T02:36:27.877000+00:00',
                                 'lastUpdatedAt': '2023-11-03T02:36:27.877000+00:00',
                                 'meshOwner': '123456789012',
                                 'resourceOwner': '123456789012',
                                 'uid': '1013368a-8d58-4b30-b08e-57347af88525',
                                 'version': 1},
                    'resourceOwner': '123456789012',
                    'spec': {'egressFilter': {'type': 'ALLOW_ALL'}},
                    'status': {'status': 'ACTIVE'},
                    'version': 1,
                }
            ],
            resources,
        )

        # These assertions are necessary to be sure that the "get_arns" function is correctly
        # deriving the ARN.
        # See the documentation on the "arn" field in appmesh.py.
        arns = p.resource_manager.get_arns(resources)
        self.assertEqual(['arn:aws:appmesh:eu-west-2:123456789012:mesh/m1'], arns)

        # The "placebo" testing library doesn't allow us to make assertions
        # linking specific api's calls to the specific mock response file
        # that will serve that request. So we will compensate here by
        # making an assertion about all the api calls and the order
        # of calls that must be made.
        self.assertEqual(
            [
                {'operation': 'ListMeshes', 'params': {}, 'service': 'appmesh'},
                {'operation': 'DescribeMesh', 'params': {'meshName': 'm1'}, 'service': 'appmesh'},
                {
                    'operation': 'GetResources',
                    'params': {
                        'ResourceARNList': ['arn:aws:appmesh:eu-west-2:123456789012:mesh/m1']
                    },
                    'service': 'resourcegroupstaggingapi',
                },
            ],
            captor.calls,
        )

    def test_reporting(self):
        f = Formatter(resource_type=AppmeshMesh.resource_type)

        # provide a fake resource
        report = f.to_csv(
            records=[
                {
                    # REPRESENTATIVE EXAMPLE !!!
                    'arn': 'arn:aws:appmesh:eu-west-2:123456789012:mesh/m1',
                    'createdAt': '9999-11-03T02:36:27.877000+00:00',
                    'lastUpdatedAt': '2023-11-03T02:36:27.877000+00:00',
                    'meshName': 'm1',
                    'meshOwner': '123456789012',
                    'metadata': {'arn': 'arn:aws:appmesh:eu-west-2:123456789012:mesh/m1',
                                 'createdAt': '2023-11-03T02:36:27.877000+00:00',
                                 'lastUpdatedAt': '2023-11-03T02:36:27.877000+00:00',
                                 'meshOwner': '123456789012',
                                 'resourceOwner': '123456789012',
                                 'uid': '1013368a-8d58-4b30-b08e-57347af88525',
                                 'version': 1},
                    'resourceOwner': '123456789012',
                    'spec': {'egressFilter': {'type': 'ALLOW_ALL'}},
                    'status': {'status': 'ACTIVE'},
                    'version': 1,
                }
            ]
        )

        # expect Formatter to inspect the definition of certain
        # fields ("name" and "date") from the AppMesh def
        # and to pick out those fields from a fake resource
        self.assertEqual([["m1", "9999-11-03T02:36:27.877000+00:00"]], report)


class TestAppmeshVirtualGateway(BaseTest):
    def test_appmesh_virtualgateway(self):
        session_factory = self.replay_flight_data('test_appmesh_virtualgateway')

        # test data has 2 VGW but only 1 has a port of 123
        p = self.load_policy(
            {
                "name": "appmesh-gateway-policy",
                "resource": "aws.appmesh-virtual-gateway",
                "filters": [
                    {
                        "type": "value",
                        "key": "spec.listeners[0].portMapping.port",
                        "op": "eq",
                        # ONLY ONE OF THE TWO RESOURCES HAS THIS PORT
                        "value": 123,
                    }
                ],
            },
            session_factory=session_factory,
        )

        captor = ApiCallCaptor.start_capture()

        # RUN THE SUT
        resources = p.run()
        resources.sort(key=lambda r: r['metadata']['arn'])

        self.assertEqual(
            [{'Tags': [{'Key': 'MyTagName', 'Value': 'm1/g1'}],
              'c7n:MatchedFilters': ['spec.listeners[0].portMapping.port'],
              'meshName': 'm1',
              'metadata': {
                  'arn': 'arn:aws:appmesh:eu-west-2:123456789012:mesh/m1/virtualGateway/g1',
                  'createdAt': '2023-11-03T02:36:27.877000+00:00',
                  'lastUpdatedAt': '2023-11-03T02:36:27.877000+00:00',
                  'meshOwner': '644160558196',
                  'resourceOwner': '644160558196',
                  'uid': '80ee4027-c8e1-49e8-99ba-cace20a57f0b',
                  'version': 1},
              'spec': {'backendDefaults': {'clientPolicy': {}},
                       'listeners': [{'portMapping': {'port': 123, 'protocol': 'http'}}],
                       'logging': {}},
              'status': {'status': 'ACTIVE'},
              'virtualGatewayName': 'g1'}],
            resources,
        )

        # These assertions are necessary to be sure that the "get_arns" function is correctly
        # deriving the ARN.
        # See the documentation on the "arn" field in appmesh.py.
        arns = p.resource_manager.get_arns(resources)
        self.assertEqual(['arn:aws:appmesh:eu-west-2:123456789012:mesh/m1/virtualGateway/g1'], arns)

        # The "placebo" testing library doesn't allow us to make assertions
        # linking specific api's calls to the specific mock response file
        # that will serve that request. So we will compensate here by
        # making an assertion about all the api calls and the order
        # of calls that must be made.
        self.assertEqual(
            [
                {'operation': 'ListMeshes', 'params': {}, 'service': 'appmesh'},
                {
                    'operation': 'ListVirtualGateways',
                    'params': {'meshName': 'm1'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'ListVirtualGateways',
                    'params': {'meshName': 'm2'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'DescribeVirtualGateway',
                    'params': {'meshName': 'm1', 'virtualGatewayName': 'g1'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'DescribeVirtualGateway',
                    'params': {'meshName': 'm1', 'virtualGatewayName': 'g2'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'GetResources',
                    'params': {
                        'ResourceARNList': [
                            'arn:aws:appmesh:eu-west-2:123456789012:mesh/m1/virtualGateway/g1',
                            'arn:aws:appmesh:eu-west-2:123456789012:mesh/m1/virtualGateway/g2',
                        ]
                    },
                    'service': 'resourcegroupstaggingapi',
                },
            ],
            captor.calls,
        )

    def test_appmesh_virtualgateway_event(self):
        session_factory = self.replay_flight_data('test_appmesh_virtualgateway_event')
        p = self.load_policy(
            {
                "name": "appmesh-gateway-policy",
                "resource": "aws.appmesh-virtual-gateway",
                "mode": {
                    "type": "cloudtrail",
                    "role": "CloudCustodian",
                    "events": [
                        {
                            "source": "appmesh.amazonaws.com",
                            "event": "CreateVirtualGateway",
                            "ids": "responseElements.virtualGateway.metadata.arn",
                        }
                    ],
                },
                "filters": [
                    {
                        "type": "value",
                        "key": "spec.listeners[0].portMapping.port",
                        "op": "eq",
                        # ONLY ONE OF THE TWO RESOURCES HAS THIS PORT
                        "value": 123,
                    },
                ]

            },
            session_factory=session_factory,
        )

        # event_data() names a file in tests/data/cwe that will drive the test execution.
        # file contains an event matching that which AWS would generate in cloud trail.
        event = {
            "detail": event_data("event-appmesh-create-virtual-gateway.json"),
            "debug": True,
        }

        captor = ApiCallCaptor.start_capture()

        # RUN THE SUT
        resources = p.push(event, None)

        self.assertEqual(
            [{'Tags': [{'Key': 'MyTagName', 'Value': 'm1/g1'}],
              'c7n:MatchedFilters': ['spec.listeners[0].portMapping.port'],
              'meshName': 'm1',
              'metadata': {
                  'arn': 'arn:aws:appmesh:eu-west-2:123456789012:mesh/m1/virtualGateway/g1',
                  'createdAt': '2023-11-03T02:36:27.877000+00:00',
                  'lastUpdatedAt': '2023-11-03T02:36:27.877000+00:00',
                  'meshOwner': '644160558196',
                  'resourceOwner': '644160558196',
                  'uid': '80ee4027-c8e1-49e8-99ba-cace20a57f0b',
                  'version': 1},
              'spec': {'backendDefaults': {'clientPolicy': {}},
                       'listeners': [{'portMapping': {'port': 123, 'protocol': 'http'}}],
                       'logging': {}},
              'status': {'status': 'ACTIVE'},
              'virtualGatewayName': 'g1'}],
            resources,
        )

        # These assertions are necessary to be sure that the "get_arns" function is
        # correctly deriving the ARN.
        # See the documentation on the "arn" field in appmesh.py.
        arns = p.resource_manager.get_arns(resources)
        self.assertEqual(['arn:aws:appmesh:eu-west-2:123456789012:mesh/m1/virtualGateway/g1'], arns)

        # The "placebo" testing library doesn't allow us to make assertions
        # linking specific api's calls to the specific mock response file
        # that will serve that request. So we will compensate here by
        # making an assertion about all the api calls and the order
        # of calls that must be made.
        self.assertEqual(
            [
                {
                    'operation': 'DescribeVirtualGateway',
                    'params': {'meshName': 'm1', 'virtualGatewayName': 'g1'},
                    'service': 'appmesh',
                },
                {
                    'operation': 'GetResources',
                    'params': {
                        'ResourceARNList': [
                            'arn:aws:appmesh:eu-west-2:123456789012:mesh/m1/virtualGateway/g1'
                        ]
                    },
                    'service': 'resourcegroupstaggingapi',
                },
            ],
            captor.calls,
        )

    def test_reporting(self):
        f = Formatter(resource_type=AppmeshVirtualGateway.resource_type,
                      extra_fields=["mesh=meshName"])

        # provide a fake resource
        report = f.to_csv(
            records=[
                {'Tags': [{'Key': 'MyTagName', 'Value': 'm1/g1'}],
                 'c7n:MatchedFilters': ['spec.listeners[0].portMapping.port'],
                 'meshName': 'm1',
                 'metadata': {
                     'arn': 'arn:aws:appmesh:eu-west-2:123456789012:mesh/m1/virtualGateway/g1',
                     'createdAt': '2023-11-03T02:36:27.877000+00:00',
                     'lastUpdatedAt': '2023-11-03T02:36:27.877000+00:00',
                     'meshOwner': '644160558196',
                     'resourceOwner': '644160558196',
                     'uid': '80ee4027-c8e1-49e8-99ba-cace20a57f0b',
                     'version': 1},
                 'spec': {'backendDefaults': {'clientPolicy': {}},
                          'listeners': [{'portMapping': {'port': 123, 'protocol': 'http'}}],
                          'logging': {}},
                 'status': {'status': 'ACTIVE'},
                 'virtualGatewayName': 'g1'}
            ],
        )

        headers = list(f.headers())

        # expect Formatter to inspect the definition of certain
        # fields ("id", "name" and "date") from the AppMesh def
        # and to pick out those fields from a fake resource
        self.assertEqual(["metadata.arn", "virtualGatewayName", "metadata.createdAt", "mesh"],
                         headers, "header")

        self.assertEqual([["arn:aws:appmesh:eu-west-2:123456789012:mesh/m1/virtualGateway/g1",
                           "g1",
                           "2023-11-03T02:36:27.877000+00:00",
                           "m1"]
                          ], report, "data")

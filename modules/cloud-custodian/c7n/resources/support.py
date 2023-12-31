# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from c7n.manager import resources
from c7n.query import QueryResourceManager, TypeInfo, DescribeSource
from c7n.utils import local_session, get_support_region


@resources.register('support-case')
class SupportCase(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'support'
        enum_spec = ('describe_cases', 'cases', None)
        global_resource = True
        filter_name = 'caseIdList'
        filter_type = 'list'
        id = 'caseId'
        name = 'displayId'
        date = 'timeCreated'
        arn = False

    def get_client(self):
        region = get_support_region(self)
        return local_session(self.session_factory).client('support', region_name=region)


class DescribeAdvisorCheck(DescribeSource):
    def resources(self, query):
        if not query:
            query = {'language': 'en'}
        return super().resources(query)


@resources.register("advisor-check")
class AdvisorCheck(QueryResourceManager):

    class resource_type(TypeInfo):
        service = "support"
        enum_spec = ('describe_trusted_advisor_checks', 'checks', None)
        detail_spec = ('describe_trusted_advisor_check_result', 'checkId', 'id', 'result')
        arn_type = "checks"
        arn_service = "trustedadvisor"
        name = id = "checkId"
        universal_taggable = object()

    source_mapping = {
        "describe": DescribeAdvisorCheck,
    }

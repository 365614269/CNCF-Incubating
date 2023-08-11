# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
#


from __future__ import absolute_import, division, print_function, unicode_literals

import re
import math

from concurrent.futures import as_completed
from datetime import timedelta, datetime
from statistics import mean

from c7n.actions import Action
from c7n.exceptions import PolicyExecutionError
from c7n.filters import ValueFilter
from c7n.filters.metrics import MetricsFilter
from c7n.filters.related import RelatedResourceFilter
from c7n.manager import resources
from c7n.query import QueryResourceManager, TypeInfo
from c7n.utils import local_session, type_schema, get_retry


@resources.register('service-quota-request')
class ServiceQuotaRequest(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'service-quotas'
        permission_prefix = 'servicequotas'
        enum_spec = ('list_requested_service_quota_change_history', 'RequestedQuotas', None)
        name = id = 'Id'
        # Service Quota Requests dont actually have arns, but we need to set an arn_type here
        # to ensure that the tests pass resource type validation
        arn_type = 'request'


@resources.register('service-quota')
class ServiceQuota(QueryResourceManager):

    batch_size = 100

    class resource_type(TypeInfo):
        service = 'service-quotas'
        permission_prefix = 'servicequotas'
        enum_spec = ('list_services', 'Services', {'MaxResults': 100})
        id = 'QuotaCode'
        arn = 'QuotaArn'
        name = 'QuotaName'
        metrics_namespace = 'AWS/Usage'

    def augment(self, resources):
        client = local_session(self.session_factory).client('service-quotas')
        retry = get_retry(('TooManyRequestsException',))

        def get_quotas(client, s):
            def _get_quotas(client, s, attr):
                quotas = {}
                token = None
                kwargs = {
                    'ServiceCode': s['ServiceCode'],
                    'MaxResults': self.batch_size
                }

                while True:
                    if token:
                        kwargs['NextToken'] = token
                    response = retry(
                        getattr(client, attr),
                        **kwargs
                    )
                    rquotas = {q['QuotaCode']: q for q in response['Quotas']}
                    token = response.get('NextToken')
                    new = set(rquotas) - set(quotas)
                    quotas.update(rquotas)
                    if token is None:
                        break
                    # ssm, ec2, kms have bad behaviors.
                    elif token and not new:
                        break
                return quotas.values()

            dquotas = {
                q['QuotaCode']: q
                for q in _get_quotas(client, s, 'list_aws_default_service_quotas')
            }
            quotas = {
                q['QuotaCode']: q
                for q in _get_quotas(client, s, 'list_service_quotas')
            }
            dquotas.update(quotas)
            return dquotas.values()

        results = []
        # NOTE TooManyRequestsException errors are reported in us-east-1 often
        # when calling the ListServiceQuotas operation
        # set the max_workers to 1 instead of self.max_workers to slow down the rate
        with self.executor_factory(max_workers=1) as w:
            futures = {}
            for r in resources:
                futures[w.submit(get_quotas, client, r)] = r

            for f in as_completed(futures):
                if f.exception():
                    raise f.exception()
                results.extend(f.result())

        return results


@ServiceQuota.filter_registry.register('usage-metric')
class UsageFilter(MetricsFilter):
    """
    Filter service quotas by usage, only compatible with service quotas
    that return a UsageMetric attribute.

    Default limit is 80%.
    Default min_period (minimal period) is 300 seconds and is automatically
    set to 60 seconds if users try to set it to anything lower than that.

    .. code-block:: yaml

        policies:
            - name: service-quota-usage-limit
              description: |
                  find any services that have usage stats of
                  over 80%
              resource: aws.service-quota
              filters:
                - UsageMetric: present
                - type: usage-metric
                  limit: 19
    """

    schema = type_schema('usage-metric', limit={'type': 'integer'}, min_period={'type': 'integer'})

    permisisons = ('cloudwatch:GetMetricStatistics',)

    annotation_key = 'c7n:UsageMetric'

    time_delta_map = {
        'MICROSECOND': 'microseconds',
        'MILLISECOND': 'milliseconds',
        'SECOND': 'seconds',
        'MINUTE': 'minutes',
        'HOUR': 'hours',
        'DAY': 'days',
        'WEEK': 'weeks',
    }

    metric_map = {
        'Maximum': max,
        'Minimum': min,
        'Average': mean,
        'Sum': sum,
        'SampleCount': len
    }

    percentile_regex = re.compile('p\\d{0,2}\\.{0,1}\\d{0,2}')

    def get_dimensions(self, usage_metric):
        dimensions = []
        for k, v in usage_metric['MetricDimensions'].items():
            dimensions.append({'Name': k, 'Value': v})
        return dimensions

    def process(self, resources, event):
        client = local_session(self.manager.session_factory).client('cloudwatch')

        end_time = datetime.utcnow()
        start_time = end_time - timedelta(1)

        limit = self.data.get('limit', 80)
        min_period = max(self.data.get('min_period', 300), 60)

        result = []

        for r in resources:
            metric = r.get('UsageMetric')
            quota = r.get('Value')
            if not metric or quota is None:
                continue
            stat = metric.get('MetricStatisticRecommendation', 'Maximum')
            if stat not in self.metric_map and self.percentile_regex.match(stat) is None:
                continue

            if 'Period' in r:
                period_unit = self.time_delta_map[r['Period']['PeriodUnit']]
                period = int(timedelta(**{period_unit: r['Period']['PeriodValue']}).total_seconds())
            else:
                period = int(timedelta(1).total_seconds())

            # Use scaling to avoid CW limit of 1440 data points
            metric_scale = 1
            if period < min_period and stat == "Sum":
                metric_scale = min_period / period
                period = min_period

            res = client.get_metric_statistics(
                Namespace=metric['MetricNamespace'],
                MetricName=metric['MetricName'],
                Dimensions=self.get_dimensions(metric),
                Statistics=[stat],
                StartTime=start_time,
                EndTime=end_time,
                Period=period,
            )
            if res['Datapoints']:
                if self.percentile_regex.match(stat):
                    # AWS CloudWatch supports percentile statistic as a statistic but
                    # when comparing against a dataset for service quotas we only care
                    # about maximum... Also note that is probably what we should do
                    # for all statistic types, but if the service quota API will return
                    # different preferred statistics, atm we will try to match that
                    op = self.metric_map['Maximum']
                elif stat == 'Sum':
                    op = self.metric_map['Maximum']
                else:
                    op = self.metric_map[stat]
                m = op([x[stat] for x in res['Datapoints']]) / metric_scale
                self.log.info(f'{r.get("ServiceName")} {r.get("QuotaName")} usage: {m}/{quota}')
                if m > (limit / 100) * quota:
                    r[self.annotation_key] = {
                        'metric': m,
                        'period': period / metric_scale,
                        'start_time': start_time,
                        'end_time': end_time,
                        'statistic': stat,
                        'limit': limit / 100 * quota,
                        'quota': quota,
                        'metric_scale': metric_scale,
                    }
                    result.append(r)
        return result


@ServiceQuota.filter_registry.register('request-history')
class RequestHistoryFilter(RelatedResourceFilter):
    """
    Filter on historical requests for service quota increases

    .. code-block:: yaml

        policies:
            - name: service-quota-increase-history-filter
              resource: aws.service-quota
              filters:
                - type: request-history
                  key: '[].Status'
                  value: CASE_CLOSED
                  value_type: swap
                  op: in

    """

    RelatedResource = 'c7n.resources.quotas.ServiceQuotaRequest'
    RelatedIdsExpression = 'QuotaCode'
    AnnotationKey = 'ServiceQuotaChangeHistory'

    schema = type_schema(
        'request-history', rinherit=ValueFilter.schema
    )

    permissions = ('servicequotas:ListRequestedServiceQuotaChangeHistory',)

    def get_related(self, resources):
        resource_manager = self.get_resource_manager()
        related_ids = self.get_related_ids(resources)
        related = resource_manager.resources()
        result = {}
        for r in related:
            result.setdefault(r[self.RelatedIdsExpression], [])
            if r[self.RelatedIdsExpression] in related_ids:
                result[r[self.RelatedIdsExpression]].append(r)
        return result

    def _add_annotations(self, related_ids, resource):
        resources = self.get_related([resource])
        a_resources = resources.get(resource[self.RelatedIdsExpression], [])
        akey = 'c7n:%s' % self.AnnotationKey
        resource[akey] = a_resources


@ServiceQuota.action_registry.register('request-increase')
class Increase(Action):
    """
    Request a limit increase for a service quota

    .. code-block:: yaml

        policies:
          - name: request-limit-increase
            resource: aws.service-quota
            filters:
              - type: value
                key: QuotaCode
                value: L-foo
            actions:
              - type: request-increase
                multiplier: 1.2
    """

    schema = type_schema('request-increase', multiplier={'type': 'number', 'minimum': 1.0})
    permissions = ('servicequotas:RequestServiceQuotaIncrease',)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('service-quotas')
        multiplier = self.data.get('multiplier', 1.2)
        error = None
        for r in resources:
            count = math.floor(multiplier * r['Value'])
            if not r['Adjustable']:
                continue
            try:
                client.request_service_quota_increase(
                    ServiceCode=r['ServiceCode'],
                    QuotaCode=r['QuotaCode'],
                    DesiredValue=count
                )
            except client.exceptions.QuotaExceededException as e:
                error = e
                self.log.error('Requested:%s exceeds quota limit for %s' % (count, r['QuotaCode']))
                continue
            except (client.exceptions.AccessDeniedException,
                    client.exceptions.DependencyAccessDeniedException,):
                raise PolicyExecutionError('Access Denied to increase quota: %s' % r['QuotaCode'])
            except (client.exceptions.NoSuchResourceException,
                    client.exceptions.InvalidResourceStateException,
                    client.exceptions.ResourceAlreadyExistsException,) as e:
                error = e
                continue
        if error:
            raise PolicyExecutionError from error

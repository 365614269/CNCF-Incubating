# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
#
from collections import defaultdict
import fnmatch
import logging
import operator

from c7n.actions import ActionRegistry
from c7n.cache import NullCache
from c7n.filters import FilterRegistry
from c7n.manager import ResourceManager

from c7n.provider import Provider, clouds
from c7n.policy import PolicyExecutionMode

from .filters import Traverse
from .utils import SEVERITY_LEVELS

log = logging.getLogger("c7n.iac")


class IACSourceProvider(Provider):
    display_name = "IAC"

    def get_session_factory(self, options):
        return lambda *args, **kw: None

    def initialize(self, options):
        pass

    def initialize_policies(self, policies, options):
        return policies


class PolicyMetadata:
    def __init__(self, policy):
        self.policy = policy

    @property
    def resource_type(self):
        return self.policy.resource_type

    @property
    def provider(self):
        return self.policy.provider_name

    @property
    def name(self):
        return self.policy.name

    @property
    def description(self):
        return self.policy.data.get("description")

    @property
    def display_category(self):
        return " ".join(self.categories)

    @property
    def categories(self):
        categories = self.policy.data.get("metadata", {}).get("category", [])
        if isinstance(categories, str):
            categories = [categories]
        if not isinstance(categories, list) or (categories and not isinstance(categories[0], str)):
            categories = []
        return categories

    @property
    def severity(self):
        value = self.policy.data.get("metadata", {}).get("severity", "")
        if isinstance(value, str):
            return value.lower()
        return ""

    @property
    def title(self):
        title = self.policy.data.get("metadata", {}).get("title", "")
        if title:
            return title
        title = f"{self.resource_type} - policy:{self.name}"
        if self.categories:
            title += f" category:{self.display_category}"
        if self.severity:
            title += f" severity:{self.severity}"
        return title

    def __repr__(self):
        return "<PolicyMetadata name:%s resource:%s>" % (self.name, self.resource_type)


class ExecutionFilter:
    supported_filters = ("policy", "type", "severity", "category", "id")

    def __init__(self, filters):
        self.filters = filters

    def __len__(self):
        return len(self.filters)

    @classmethod
    def parse(cls, options):
        """cli option filtering support

        --filters "type=aws_sqs_queue,aws_rds_* policy=*encryption* severity=high"
        """
        if not options.filters:
            return cls(defaultdict(list))

        filters = defaultdict(list)
        for kv in options.filters.split(" "):
            if "=" not in kv:
                raise ValueError("key=value pair missing `=`")
            k, v = kv.split("=")
            if k not in cls.supported_filters:
                raise ValueError("unsupported filter %s" % k)
            if "," in v:
                v = v.split(",")
            else:
                v = [v]
            filters[k] = v
        cls._validate_severities(filters)
        return cls(filters)

    @classmethod
    def _validate_severities(cls, filters):
        invalid_severities = set()
        if filters["severity"]:
            invalid_severities = set(filters["severity"]).difference(SEVERITY_LEVELS)
        if invalid_severities:
            raise ValueError("invalid severity for filtering %s" % (", ".join(invalid_severities)))

    def filter_attribute(self, filter_name, attribute, items):
        if not self.filters[filter_name] or not items:
            return items
        results = []
        op_class = isinstance(items[0], dict) and operator.itemgetter or operator.attrgetter
        op = op_class(attribute)
        for f in self.filters[filter_name]:
            for i in items:
                v = op(i)
                if not v:
                    continue
                elif isinstance(v, list):
                    for el in v:
                        if fnmatch.fnmatch(el, f):
                            results.append(i)
                            break
                elif fnmatch.fnmatch(v, f):
                    results.append(i)
        return results

    def _filter_policy_severity(self, policies):
        # if we have a single severity filter we default to filtering
        # all severities at a higher level. ie filtering on medium,
        # gets and critcial, high.
        if not self.filters["severity"]:
            return policies

        def filter_severity(p):
            p_slevel = SEVERITY_LEVELS.get(p.severity) or SEVERITY_LEVELS.get("unknown")
            f_slevel = SEVERITY_LEVELS[self.filters["severity"][0]]
            return p_slevel <= f_slevel

        if len(self.filters["severity"]) == 1:
            return list(filter(filter_severity, policies))

        results = []
        # if we have mulitple values, match on each, note no support for glob on severity
        # since its a controlled vocab.
        fseverities = set(self.filters["severity"])
        for p in policies:
            if (p.severity or "unknown") not in fseverities:
                continue
            results.append(p)
        return results

    def filter_policies(self, policies):
        policies = list(map(PolicyMetadata, policies))
        policies = self.filter_attribute("policy", "name", policies)
        policies = self.filter_attribute("category", "categories", policies)
        policies = self._filter_policy_severity(policies)
        return [pm.policy for pm in policies]

    def _filter_resource_id(self, resources):
        if not self.filters["id"]:
            return resources
        results = []
        for r in resources:
            id = r["__tfmeta"]["path"].split(".", 1)[-1]
            for idf in self.filters["id"]:
                if fnmatch.fnmatch(id, idf):
                    results.append(r)
        return results

    def filter_resources(self, rtype, resources):
        if not self.filter_attribute("type", "type", [{"type": rtype}]):
            return []
        resources = self._filter_resource_id(resources)
        return resources


class CollectionRunner:
    def __init__(self, policies, options, reporter):
        self.policies = policies
        self.options = options
        self.reporter = reporter

    def run(self) -> bool:
        # return value is used to signal process exit code.
        event = self.get_event()
        provider = self.get_provider()

        if not provider.match_dir(self.options.source_dir):
            log.warning("no %s source files found" % provider.type)
            return True

        graph = provider.parse(self.options.source_dir)

        for p in self.policies:
            p.expand_variables(p.get_variables())
            p.validate()

        self.reporter.on_execution_started(self.policies, graph)
        # consider inverting this order to allow for results grouped by policy
        # at the moment, we're doing results grouped by resource.
        found = False
        for rtype, resources in graph.get_resources_by_type():
            if self.options.exec_filter:
                resources = self.options.exec_filter.filter_resources(rtype, resources)
            if not resources:
                continue
            for p in self.policies:
                if not self.match_type(rtype, p):
                    continue
                result_set = self.run_policy(p, graph, resources, event)
                if result_set:
                    self.reporter.on_results(result_set)
                    found = True
        self.reporter.on_execution_ended()
        return found

    def run_policy(self, policy, graph, resources, event):
        event = dict(event)
        event.update({"graph": graph, "resources": resources})
        return policy.push(event)

    def get_provider(self):
        provider_name = {p.provider_name for p in self.policies}.pop()
        provider = clouds[provider_name]()
        return provider

    def get_event(self):
        return {"config": self.options}

    @staticmethod
    def match_type(rtype, p):
        if isinstance(p.resource_type, str):
            return fnmatch.fnmatch(rtype, p.resource_type.split(".", 1)[-1])
        found = False
        if isinstance(p.resource_type, list):
            for pr in p.resource_type:
                if fnmatch.fnmatch(rtype, pr.split(".", 1)[-1]):
                    found = True
                    break
        return found


class IACSourceMode(PolicyExecutionMode):
    @property
    def manager(self):
        return self.policy.resource_manager

    def run(self, event, ctx):
        if not self.policy.is_runnable(event):
            return []

        resources = event["resources"]
        resources = self.manager.filter_resources(resources, event)
        return self.as_results(resources)

    def as_results(self, resources):
        return ResultSet([PolicyResourceResult(r, self.policy) for r in resources])


class ResultSet(list):
    pass


class PolicyResourceResult:
    def __init__(self, resource, policy):
        self.resource = resource
        self.policy = policy

    def as_dict(self):
        return {
            "policy": dict(self.policy.data),
            "resource": dict(self.resource),
            "file_path": str(self.resource.src_dir / self.resource.filename),
            "file_line_start": self.resource.line_start,
            "file_line_end": self.resource.line_end,
        }


class IACResourceManager(ResourceManager):
    filter_registry = FilterRegistry("iac.filters")
    action_registry = ActionRegistry("iac.actions")
    log = log

    def __init__(self, ctx, data):
        self.ctx = ctx
        self.data = data
        self._cache = NullCache(None)
        self.session_factory = lambda: None
        self.filters = self.filter_registry.parse(self.data.get("filters", []), self)
        self.actions = self.action_registry.parse(self.data.get("actions", []), self)

    def get_resource_manager(self, resource_type, data=None):
        return self.__class__(self.ctx, data or {})


IACResourceManager.filter_registry.register("traverse", Traverse)


class IACResourceMap(object):
    resource_class = None

    def __init__(self, prefix):
        self.prefix = prefix

    def __contains__(self, k):
        if k.startswith(self.prefix):
            return True
        return False

    def __getitem__(self, k):
        if k.startswith(self.prefix):
            return self.resource_class
        raise KeyError(k)

    def __iter__(self):
        return iter(())

    def notify(self, *args):
        pass

    def keys(self):
        return ()

    def items(self):
        return ()

    def get(self, k, default=None):
        # that the resource is in the map has alerady been verified
        # we get the unprefixed resource on get
        return self.resource_class


class ResourceGraph:
    def __init__(self, resource_data, src_dir):
        self.resource_data = resource_data
        self.src_dir = src_dir

    def __len__(self):
        raise NotImplementedError()

    def get_resource_by_type(self):
        raise NotImplementedError()

    def resolve_refs(self, resource, target_type):
        raise NotImplementedError()

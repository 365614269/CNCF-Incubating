# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

try:
    from functools import lru_cache
except ImportError:
    from backports.functools_lru_cache import lru_cache

import logging
import re
import os

from c7n.exceptions import PolicyValidationError
from c7n.policy import PolicyCollection
from c7n.resources import load_resources
try:
    from c7n import schema
except ImportError:
    # serverless execution doesn't use jsonschema
    schema = None
from c7n.structure import StructureParser
from c7n.utils import load_file


log = logging.getLogger('custodian.loader')


class SchemaValidator:

    def __init__(self):
        # mostly useful for interactive debugging
        self.schema = None
        self.validator = None

    def validate(self, policy_data, resource_types=None):
        # before calling validate, gen_schema needs to be invoked
        # with the qualified resource types in policy_data.
        if resource_types is None:
            resource_types = StructureParser().get_resource_types(policy_data)
        self.gen_schema(tuple(sorted(resource_types)))
        errors = self._validate(policy_data)
        return errors or []

    def _validate(self, policy_data):
        errors = list(self.validator.iter_errors(policy_data))
        if not errors:
            return schema.check_unique(policy_data) or []
        try:
            resp = schema.policy_error_scope(
                schema.specific_error(errors[0]), policy_data)
            name = isinstance(
                errors[0].instance,
                dict) and errors[0].instance.get(
                    'name',
                    'unknown') or 'unknown'
            return [resp, name]
        except Exception:
            logging.exception(
                "schema-validator: specific_error failed, traceback, followed by fallback")

        return list(filter(None, [
            errors[0],
            schema.best_match(self.validator.iter_errors(policy_data)),
        ]))

    def gen_schema(self, resource_types):
        self.validator = v = self._gen_schema(resource_types)
        # alias for debugging
        self.schema = v.schema
        return self.validator

    @lru_cache(maxsize=32)
    def _gen_schema(self, resource_types):
        if schema is None:
            raise RuntimeError("missing jsonschema dependency")
        rt_schema = schema.generate(resource_types)
        schema.JsonSchemaValidator.check_schema(rt_schema)
        return schema.JsonSchemaValidator(rt_schema)


class PolicyLoader:

    default_schema_validate = bool(schema)
    default_schema_class = SchemaValidator
    collection_class = PolicyCollection

    def __init__(self, config):
        self.policy_config = config
        self.validator = SchemaValidator()
        self.structure = StructureParser()
        self.seen_types = set()

    def load_file(self, file_path, format=None):
        # should we do os.path.expanduser here?
        if not os.path.exists(file_path):
            raise IOError("Invalid path for config %r" % file_path)
        policy_data = load_file(file_path, format=format)
        return self.load_data(policy_data, file_path)

    def _handle_missing_resources(self, policy_data, missing):
        # for an invalid resource type catch and try to associate
        # it to the policy by name.
        for p in policy_data.get('policies', ()):
            pr = p['resource']
            if '.' not in pr:
                pr = "aws.%s" % pr
            if pr in missing:
                raise PolicyValidationError(
                    "Policy:%s references an unknown resource:%s" % (
                        p['name'], p['resource']))

    def load_data(self, policy_data, file_uri, validate=None,
                  session_factory=None, config=None):
        self.structure.validate(policy_data)

        # Use passed in policy exec configuration or default on loader
        config = config or self.policy_config

        # track policy resource types and only load if needed.
        rtypes = set(self.structure.get_resource_types(policy_data))

        missing = load_resources(list(rtypes))
        if missing:
            self._handle_missing_resources(policy_data, missing)

        if schema and (validate is not False or (
                validate is None and
                self.default_schema_validate)):
            errors = self.validator.validate(policy_data, tuple(rtypes))
            if errors:
                raise PolicyValidationError(
                    "Failed to validate policy %s\n %s\n" % (
                        errors[1], errors[0]))

        collection = self.collection_class.from_data(
            policy_data, config, session_factory)

        # non schema validation of policies isnt optional its
        # become a lazy initialization point for resources.
        #
        # it would be good to review where we do validation
        # as we also have to do after provider policy
        # initialization due to the region expansion.
        #
        # ie we should defer this to callers
        # [p.validate() for p in collection]
        return collection


class SourceLocator:
    def __init__(self, filename):
        self.filename = filename
        self.policies = None

    def find(self, name):
        """Find returns the file and line number for the policy."""
        if self.policies is None:
            self.load_file()
        line = self.policies.get(name, None)
        if line is None:
            return ""
        filename = os.path.basename(self.filename)
        return f"{filename}:{line}"

    def load_file(self):
        self.policies = {}
        r = re.compile(r'^\s+(-\s+)?name: ([\w-]+)\s*$')
        with open(self.filename) as f:
            for i, line in enumerate(f, 1):
                m = r.search(line)
                if m:
                    self.policies[m.group(2)] = i


class DirectoryLoader(PolicyLoader):
    def load_directory(self, directory, validate=True, recurse=True):
        structure = StructureParser()

        def _validate(data):
            errors = []
            try:
                structure.validate(data)
            except PolicyValidationError as e:
                log.error("Configuration invalid: {}".format(data))
                log.error("%s" % e)
                errors.append(e)
                return errors
            rtypes = structure.get_resource_types(data)
            load_resources(rtypes)
            schm = schema.generate(rtypes)
            errors += schema.validate(data, schm)
            return errors

        def _load(path, raw_policies, errors, do_validate):
            for root, dirs, files in os.walk(path):
                files = [f for f in files if not is_hidden(f)]
                dirs[:] = [d for d in dirs if not is_hidden(d)]

                for name in files:
                    fmt = name.rsplit('.', 1)[-1]
                    if fmt in ('yaml', 'yml', 'json',):
                        data = load_file(os.path.join(root, name))
                        if do_validate:
                            errors += _validate(data)
                        raw_policies.append(data)
                if not recurse:
                    return
                for name in dirs:
                    _load(os.path.abspath(name), raw_policies, errors, do_validate)

        policy_collections, all_errors = [], []
        _load(directory, policy_collections, all_errors, validate)

        if all_errors:
            raise PolicyValidationError(all_errors)

        policies = []
        for p in policy_collections:
            if not p.get('policies'):
                continue
            policies.extend(p['policies'])

        names = []
        for p in policies:
            if p['name'] in names:
                raise PolicyValidationError(
                    f"Duplicate Key Error: policy:{p['name']} already exists")
            else:
                names.append(p['name'])

        return self.load_data({'policies': policies}, directory, validate=validate)


def is_hidden(path):
    for part in os.path.split(path):
        if part != '.' and part.startswith('.'):
            return True

    return False

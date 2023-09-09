# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
#
import json
import os
import subprocess
from pathlib import Path
from unittest.mock import ANY
from urllib.request import urlopen

import jsonschema
import pytest
from click.testing import CliRunner

from c7n.config import Config
from c7n.resources import load_resources

try:
    from c7n_left import cli, core, output, policy as policy_core
    from c7n_left.providers.terraform.provider import (
        TerraformProvider,
        TerraformResourceManager,
        extract_mod_stack,
    )
    from c7n_left.providers.terraform.graph import Resolver
    from c7n_left.providers.terraform.filters import Taggable

    LEFT_INSTALLED = True
except ImportError:
    pytest.skip(reason="c7n_left not installed", allow_module_level=True)
    LEFT_INSTALLED = False
else:
    load_resources(("terraform.*",))

cur_dir = Path(os.curdir).absolute()
terraform_dir = Path(__file__).parent.parent.parent.parent / "tests" / "terraform"
terraform_dir = terraform_dir.relative_to(cur_dir)


class ResultsReporter:
    def __init__(self):
        self.results = []

    def on_execution_started(self, policies, graph):
        pass

    def on_execution_ended(self):
        pass

    def on_results(self, results):
        self.results.extend(results)


def run_policy(policy, terraform_dir, tmp_path):
    (tmp_path / "policies.json").write_text(json.dumps({"policies": [policy]}, indent=2))
    config = Config.empty(
        policy_dir=tmp_path, source_dir=terraform_dir, exec_filter=None, var_files=()
    )
    policies = policy_core.load_policies(tmp_path, config)
    reporter = ResultsReporter()
    core.CollectionRunner(policies, config, reporter).run()
    return reporter.results


class PolicyEnv:
    def __init__(self, policy_dir):
        self.policy_dir = policy_dir

    def get_policies(self):
        config = Config.empty(policy_dir=self.policy_dir)
        policies = policy_core.load_policies(self.policy_dir, config)
        return policies

    def get_graph(self, root_module):
        return TerraformProvider().parse(root_module)

    def get_selection(self, filter_expression):
        return core.ExecutionFilter.parse(Config.empty(filters=filter_expression))

    def write_tf(self, content, path="main.tf"):
        tf_file = self.policy_dir / path
        tf_file.write_text(content)

    def write_policy(self, policy, path="policy.json"):
        policy_file = self.policy_dir / path
        extant = {"policies": []}
        if policy_file.exists():
            extant = json.loads(policy_file.read_text())
        extant["policies"].append(policy)
        policy_file.write_text(json.dumps(extant))

    def run(self, policy_dir=None, terraform_dir=None):
        config = Config.empty(
            policy_dir=policy_dir or self.policy_dir,
            source_dir=terraform_dir or self.policy_dir,
            exec_filter=None,
            var_files=(),
        )
        policies = policy_core.load_policies(config.policy_dir, config)
        reporter = ResultsReporter()
        core.CollectionRunner(policies, config, reporter).run()
        return reporter.results


@pytest.fixture
def policy_env(tmp_path):
    return PolicyEnv(tmp_path)


def test_load_policy(test):
    test.load_policy({"name": "check1", "resource": "terraform.aws_s3_bucket"}, validate=True)
    test.load_policy({"name": "check2", "resource": ["terraform.aws_s3_bucket"]}, validate=True)
    test.load_policy({"name": "check3", "resource": ["terraform.aws_*"]}, validate=True)


def test_load_policy_dir(tmp_path):
    write_output_test_policy(tmp_path)
    policies = policy_core.load_policies(tmp_path, Config.empty())
    assert len(policies) == 1


def test_extract_mod_stack():
    stack = extract_mod_stack("module.db.module.db_instance.aws_db_instance.this[0]")
    assert stack == [
        "module.db",
        "module.db.module.db_instance",
        "module.db.module.db_instance.aws_db_instance.this[0]",
    ]


def test_taggable_module_resource():
    assert (
        Taggable.is_taggable(
            (
                {
                    '__tfmeta': {
                        'label': 'aws_security_group',
                        'path': 'module.my_module.aws_security_group.this_name_prefix[0]',
                    }
                },
            )
        )
        is True
    )


DB_MODULE_TF = """
module "db" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 3.0"

  identifier = "demodb"

  engine            = "mysql"
  engine_version    = "5.7.19"
  instance_class    = "db.t2.large"
  allocated_storage = 5
  auto_minor_version_upgrade = true
  backup_retention_period =  0

  name     = "demodb"
  username = "user"
  port     = "3306"
}
"""


@pytest.mark.skipif(
    os.environ.get('GITHUB_ACTIONS') is None,
    reason="runs in github actions as it requires network access for tf init",
)
def test_mod_reference(tmp_path):
    (tmp_path / "main.tf").write_text(DB_MODULE_TF)
    subprocess.check_call(args="terraform init", shell=True, cwd=tmp_path)
    results = run_policy(
        {
            "name": "check-backup",
            "resource": "terraform.aws_db_instance",
            "filters": [{"backup_retention_period": 0}],
        },
        tmp_path,
        tmp_path,
    )
    assert len(results) == 1
    assert results[0].resource['__tfmeta']['filename'] == 'main.tf'
    assert results[0].resource['__tfmeta']['type'] == 'module'
    assert results[0].resource['__tfmeta']['refs'] == [
        'module.db.module.db_instance.aws_db_instance.this[0]'
    ]


def test_graph_resolver():
    graph = TerraformProvider().parse(terraform_dir / "vpc_flow_logs")
    resolver = graph.build()

    log = list(graph.get_resources_by_type("aws_flow_log"))[0][1][0]
    iam_role = list(resolver.resolve_refs(log, ("aws_iam_role",)))[0]

    assert iam_role["name_prefix"] == "example"
    assert {r["__tfmeta"]["label"] for r in resolver.resolve_refs(log)} == set(
        ("aws_vpc", "aws_cloudwatch_log_group", "aws_iam_role")
    )


def test_resource_type_interface():
    rtype = TerraformResourceManager(None, {}).get_model()
    assert rtype.id == "id"


def test_graph_resolver_inner_block_ref():
    graph = TerraformProvider().parse(terraform_dir / "aws_code_build_vpc")
    resolver = graph.build()
    project = list(graph.get_resources_by_type("aws_codebuild_project"))[0][1][0]
    assert {r["__tfmeta"]["label"] for r in resolver.resolve_refs(project)} == set(
        ("aws_vpc", "aws_security_group", "aws_iam_role", "aws_subnet")
    )


def test_graph_resolver_local_modules():
    graph = TerraformProvider().parse(terraform_dir / "local_modules/root")
    queues = list(graph.get_resources_by_type("aws_sqs_queue"))
    # prove that we got the parent module resources.
    assert len(queues[0][1]) == 2
    assert queues[0][1][1]["name"] == "parent_queue"


def test_graph_resolver_id():
    resolver = Resolver()
    assert resolver.is_id_ref("4b3db3ec-98ad-4382-a460-d8e392d128b7") is True
    assert resolver.is_id_ref("a" * 36) is False


def test_event_env(policy_env, test):
    policy_env.write_tf(
        """
resource "aws_cloudwatch_log_group" "yada" {
  name = "Bar"
}
        """
    )
    policy_env.write_policy(
        {
            "name": "check-env",
            "resource": "terraform.aws_cloudwatch_log_group",
            "filters": [
                {"type": "event", "key": "env.REPO", "value": "cloud-custodian/cloud-custodian"}
            ],
        }
    )
    test.change_environment(REPO="cloud-custodian/cloud-custodian")
    results = policy_env.run()
    assert len(results) == 1


def test_value_from_with_env_interpolate(policy_env, test):
    policy_env.write_tf(
        """
resource "aws_cloudwatch_log_group" "yada" {
   name = "Bar"
}
resource "aws_cloudwatch_log_group" "bada" {
   name = "Baz"
}
        """
    )
    (policy_env.policy_dir / "exceptions").mkdir()
    exceptions_file = policy_env.policy_dir / "exceptions" / "exceptions.json"
    exceptions_file.write_text(
        json.dumps({"policy": {"tagging": ["aws_cloudwatch_log_group.yada"]}})
    )
    test.change_environment(PWD=str(policy_env.policy_dir.absolute()))
    policy_env.write_policy(
        {
            "name": "check-exceptions",
            "resource": "terraform.aws_cloudwatch_log_group",
            "filters": [
                {"tag:Env": "absent"},
                {
                    "type": "value",
                    "value_from": {
                        "url": "file://{env[PWD]}/exceptions/exceptions.json",
                        "expr": "policy.tagging",
                    },
                    "op": "not-in",
                    "key": "__tfmeta.path",
                },
            ],
        }
    )

    results = policy_env.run()
    assert len(results) == 1


def test_data_policy(policy_env):
    policy_env.write_tf(
        """
data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  owners = ["099720109477"] # Canonical
}
        """
    )
    policy_env.write_policy({"name": "check-data", "resource": "terraform.data.aws_ami"})
    results = policy_env.run()
    assert len(results) == 1


def test_block_types(policy_env):
    # module block type handled separately
    policy_env.write_tf(
        """
locals {
   name = "Yada"
}
resource "aws_cloudwatch_log_group" "yada" {
  name = local.name
}
terraform {
  experiments = [example]
}
moved {
  from = aws_instance.known
  to   = aws_cloudwatch_log_group.yada
}
provider "aws" {
  region = "us-east-1"
}

variable "name" {
  type = string
  default = "theodora"
}
output "news" {
  value = "https://lwn.net"
}
    """
    )
    policy_env.write_policy({"name": "check-blocks", "resource": "terraform.*"})
    results = policy_env.run()
    assert len(results) == 7
    assert {r.resource["__tfmeta"]["type"] for r in results} == {
        "moved",
        "local",
        "resource",
        "provider",
        "variable",
        "output",
        "terraform",
    }


def test_provider_tag_augment(policy_env):
    policy_env.write_tf(
        """
resource "aws_cloudwatch_log_group" "yada" {
  name = "Yada"
}
resource "aws_cloudwatch_log_stream" "foo" {
  name           = "SampleLogStream1234"
  log_group_name = aws_cloudwatch_log_group.yada.name
}
provider "aws" {
 default_tags {
   tags = {
     Env = "Test"
   }
 }
}
provider "google" {
  project     = "my-project-id"
  region      = "us-central1"
}
        """
    )
    policy_env.write_policy(
        {"name": "check-tags", "resource": "terraform.*", "filters": [{"tag:Env": "Test"}]}
    )
    results = policy_env.run()
    assert len(results) == 1
    assert results[0].resource['name'] == 'Yada'


def test_value_tag_prefix(policy_env):
    policy_env.write_tf(
        """
locals {
  name = "forum"
}

resource "aws_cloudwatch_log_group" "test_group_1" {
  name = "${local.name}-1"
  tags = {
    Application = "login"
  }
}

resource "aws_cloudwatch_log_group" "test_group_2" {
  name = "${local.name}-2"
  tags = {
    App = "AuthZ"
    Env = "Dev"
  }
}
        """
    )
    policy_env.write_policy(
        {
            "name": "check-tags",
            "resource": "terraform.aws_*",
            "filters": [{"tag:App": "absent"}, {"tag:Env": "absent"}],
        }
    )

    results = policy_env.run()
    assert len(results) == 1
    assert results[0].resource['name'] == 'forum-1'


def test_taggable(policy_env):
    policy_env.write_tf(
        """
resource "aws_cloudwatch_log_group" "yada" {
  name = "Yada"
}
resource "aws_cloudwatch_log_stream" "foo" {
  name           = "SampleLogStream1234"
  log_group_name = aws_cloudwatch_log_group.yada.name
}
        """
    )
    policy_env.write_policy(
        {"name": "check-tags", "resource": "terraform.*", "filters": ["taggable"]}
    )
    results = policy_env.run()
    assert len(results) == 1
    assert results[0].resource['name'] == 'Yada'


def test_traverse_to_data(policy_env):
    policy_env.write_tf(
        """
data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  owners = ["099720109477"] # Canonical
}

resource "aws_instance" "app" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"
}
        """
    )
    policy_env.write_policy(
        {
            "name": "check-image",
            "resource": "terraform.aws_instance",
            "filters": [
                {"type": "traverse", "resources": "data.aws_ami", "attrs": [{"owners": "present"}]}
            ],
        }
    )
    graph = TerraformProvider().parse(policy_env.policy_dir)
    assert not list(graph.get_resources_by_type('aws_ami'))
    assert list(graph.get_resources_by_type('data.aws_ami'))

    results = policy_env.run()
    assert len(results) == 1


def test_traverse_multi_resource_multi_set(tmp_path):
    resources = run_policy(
        {
            "name": "check-link",
            "resource": "terraform.aws_s3_bucket",
            "filters": [
                {
                    "type": "traverse",
                    "resources": "aws_s3_bucket_ownership_controls",
                    "attrs": [
                        {
                            "type": "value",
                            "key": "rule.object_ownership",
                            "value": ["BucketOwnerPreferred", "BucketOwnerEnforced"],
                            "op": "in",
                        }
                    ],
                }
            ],
        },
        terraform_dir / "s3_ownership",
        tmp_path,
    )
    assert len(resources) == 2
    assert {r.resource.name for r in resources} == {
        "aws_s3_bucket.owner_enforced",
        "aws_s3_bucket.owner_preferred",
    }


def test_traverse_filter_not_found(tmp_path):
    resources = run_policy(
        {
            "name": "check-link",
            "resource": "terraform.aws_codebuild_project",
            "filters": [
                {
                    "type": "traverse",
                    "resources": ["aws_security_group", "aws_vpc"],
                    "attrs": [{"tag:Env": "Prod"}],
                }
            ],
        },
        terraform_dir / "aws_code_build_vpc",
        tmp_path,
    )
    assert len(resources) == 0


def test_traverse_filter_not_found_matches(tmp_path):
    resources = run_policy(
        {
            "name": "check-link",
            "resource": "terraform.aws_codebuild_project",
            "filters": [
                {
                    "type": "traverse",
                    "resources": ["aws_security_group", "aws_vpc"],
                    "count": 0,
                    "attrs": [{"tag:Env": "Prod"}],
                }
            ],
        },
        terraform_dir / "aws_code_build_vpc",
        tmp_path,
    )
    assert len(resources) == 1


def test_traverse_filter_multi_hop(tmp_path):
    resources = run_policy(
        {
            "name": "check-link",
            "resource": "terraform.aws_codebuild_project",
            "filters": [
                {
                    "type": "traverse",
                    "resources": ["aws_security_group", "aws_vpc"],
                    "count": 1,
                    "attrs": [{"tag:Env": "Dev"}],
                }
            ],
        },
        terraform_dir / "aws_code_build_vpc",
        tmp_path,
    )
    assert len(resources) == 1


def test_boolean(tmp_path):
    resources = run_policy(
        {
            "name": "check-link",
            "resource": "terraform.aws_s3_bucket",
            "filters": [{"not": [{"server_side_encryption_configuration": "present"}]}],
        },
        terraform_dir / "aws_s3_encryption_audit",
        tmp_path,
    )
    assert len(resources) == 1
    assert resources[0].resource["bucket"] == "c7n-aws-s3-encryption-audit-test-c"


def test_provider_parse():
    graph = TerraformProvider().parse(terraform_dir / "ec2_stop_protection_disabled")
    resource_types = list(graph.get_resources_by_type("aws_subnet"))
    rtype, resources = resource_types.pop()
    assert rtype == "aws_subnet"
    assert resources[0]["__tfmeta"] == {
        "type": "resource",
        "label": "aws_subnet",
        "path": "aws_subnet.example",
        "filename": "network.tf",
        "line_start": 5,
        "line_end": 8,
        "src_dir": Path("tests") / "terraform" / "ec2_stop_protection_disabled",
    }


@pytest.fixture
def var_tf_setup(tmp_path):
    (tmp_path / "tf").mkdir()
    (tmp_path / "tf" / "main.tf").write_text(
        """
variable balancer_type {
  type = string
  default = "application"
}

resource "aws_alb" "positive1" {
  name               = "test-lb-tf"
  internal           = false
  load_balancer_type = var.balancer_type
  subnets            = aws_subnet.public.*.id
}
        """
    )


#
# we can't test env vars, as they need to be set before
# we import tfparse. manually verified they work as expected.
#
# def xtest_graph_var_env(test, tmp_path, var_tf_setup):
#    os.putenv("TF_VAR_balancer_type", "network")
#    graph = TerraformProvider().parse(tmp_path / "tf")
#    resources = list(graph.get_resources_by_type("aws_alb"))
#    assert resources[0][1][0]['load_balancer_type'] == 'network'


def test_graph_non_root_var_file(tmp_path, var_tf_setup):
    (tmp_path / "vars.tfvars").write_text('balancer_type = "network"')
    graph = TerraformProvider().parse(tmp_path / "tf", (tmp_path / "vars.tfvars",))
    resources = list(graph.get_resources_by_type("aws_alb"))
    assert resources[0][1][0]['load_balancer_type'] == 'network'


def test_graph_var_auto_default_json(tmp_path, var_tf_setup):
    (tmp_path / "tf" / "terraform.tfvars.json").write_text(json.dumps({'balancer_type': 'network'}))
    graph = TerraformProvider().parse(tmp_path / "tf")
    resources = list(graph.get_resources_by_type("aws_alb"))
    assert resources[0][1][0]['load_balancer_type'] == 'network'


def test_graph_var_auto_default(tmp_path, var_tf_setup):
    (tmp_path / "tf" / "terraform.tfvars").write_text('balancer_type = "network"')
    graph = TerraformProvider().parse(tmp_path / "tf")
    resources = list(graph.get_resources_by_type("aws_alb"))
    assert resources[0][1][0]['load_balancer_type'] == 'network'


def test_graph_var_auto(tmp_path, var_tf_setup):
    (tmp_path / "tf" / "vars.auto.tfvars").write_text('balancer_type = "network"')
    graph = TerraformProvider().parse(tmp_path / "tf")
    resources = list(graph.get_resources_by_type("aws_alb"))
    assert resources[0][1][0]['load_balancer_type'] == 'network'


def test_graph_var_file_abs(tmp_path, var_tf_setup):
    (tmp_path / "tf" / "vars.tfvars").write_text('balancer_type = "network"')
    graph = TerraformProvider().parse(tmp_path / "tf", (tmp_path / "tf" / "vars.tfvars",))
    resources = list(graph.get_resources_by_type("aws_alb"))
    assert resources[0][1][0]['load_balancer_type'] == 'network'


def test_graph_var_file(tmp_path, var_tf_setup):
    (tmp_path / "tf" / "vars.tfvars").write_text('balancer_type = "network"')
    graph = TerraformProvider().parse(tmp_path / "tf", ("vars.tfvars",))
    resources = list(graph.get_resources_by_type("aws_alb"))
    assert resources[0][1][0]['load_balancer_type'] == 'network'


def test_cli_var_file(tmp_path, var_tf_setup, debug_cli_runner):
    (tmp_path / "tf" / "vars.tfvars").write_text('balancer_type = "network"')
    (tmp_path / "policy.json").write_text(
        json.dumps(
            {
                "policies": [
                    {
                        "name": "check-multi",
                        "resource": ["terraform.aws_alb"],
                        "filters": [{"load_balancer_type": "network"}],
                    }
                ]
            }
        )
    )
    result = debug_cli_runner.invoke(
        cli.cli,
        [
            "run",
            "-p",
            str(tmp_path),
            "-d",
            str(tmp_path / "tf"),
            "-o",
            "json",
            "--var-file",
            tmp_path / "tf" / "vars.tfvars",
            "--output-file",
            str(tmp_path / "output.json"),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 1
    data = json.loads((tmp_path / "output.json").read_text())
    assert len(data["results"]) == 1


def test_multi_provider_resource_glob_policy(tmp_path, debug_cli_runner):
    (tmp_path / "policy.yaml").write_text(
        """
        policies:
          - name: check-multi-provider
            resource: "terraform.*"
        """
    )
    (tmp_path / "tf").mkdir()
    (tmp_path / "tf" / "main.tf").write_text(
        """
terraform {
  required_providers {
    oci = {
      source = "oracle/oci"
    }
  }
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

resource "aws_cloudwatch_log_group" "yada" {
  name = "Yada"
}

resource "google_storage_bucket" "static-site" {
  name     = "image-store.com"
  location = "EU"
}        """
    )

    result = debug_cli_runner.invoke(
        cli.cli,
        [
            "run",
            "-p",
            str(tmp_path),
            "-d",
            str(tmp_path / "tf"),
            "-o",
            "json",
            "--output-file",
            str(tmp_path / "output.json"),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 1
    data = json.loads((tmp_path / "output.json").read_text())
    assert len(data["results"]) == 4


def test_multi_resource_list_policy(tmp_path):
    (tmp_path / "policy.json").write_text(
        json.dumps(
            {
                "policies": [
                    {
                        "name": "check-multi",
                        "resource": ["terraform.aws_alb", "terraform.aws_lb"],
                    }
                ]
            }
        )
    )

    (tmp_path / "tf").mkdir()

    (tmp_path / "tf" / "main.tf").write_text(
        """
resource "aws_alb" "positive1" {
  name               = "test-lb-tf"
  internal           = false
  load_balancer_type = "network"
  subnets            = aws_subnet.public.*.id
}

resource "aws_lb" "positive3" {
  name               = "test-lb-tf"
  internal           = false
  load_balancer_type = "network"
  subnets            = aws_subnet.public.*.id
}
        """
    )
    runner = CliRunner()
    result = runner.invoke(
        cli.cli,
        [
            "run",
            "-p",
            str(tmp_path),
            "-d",
            str(tmp_path / "tf"),
            "-o",
            "json",
            "--output-file",
            str(tmp_path / "output.json"),
        ],
    )
    assert result.exit_code == 1
    data = json.loads((tmp_path / "output.json").read_text())
    assert len(data["results"]) == 2


def test_multi_resource_glob_policy(tmp_path):
    (tmp_path / "policy.json").write_text(
        json.dumps(
            {
                "policies": [
                    {
                        "name": "check-wild",
                        "resource": "terraform.aws_*",
                    }
                ]
            }
        )
    )
    runner = CliRunner()
    result = runner.invoke(
        cli.cli,
        [
            "run",
            "-p",
            str(tmp_path),
            "-d",
            str(terraform_dir / "aws_lambda_check_permissions"),
            "-o",
            "json",
            "--output-file",
            str(tmp_path / "output.json"),
        ],
    )
    assert result.exit_code == 1
    data = json.loads((tmp_path / "output.json").read_text())
    assert len(data["results"]) == 2


def write_output_test_policy(tmp_path, policy=None, policy_path="policy.json"):
    policies = (
        policy
        and {"policies": [policy]}
        or {
            "policies": [
                {
                    "name": "check-bucket",
                    "resource": "terraform.aws_s3_bucket",
                    "description": "a description",
                    "filters": [{"server_side_encryption_configuration": "absent"}],
                }
            ]
        }
    )
    (tmp_path / policy_path).write_text(json.dumps(policies))


def test_cli_no_policies(tmp_path, caplog):
    runner = CliRunner()
    runner.invoke(
        cli.cli,
        [
            "run",
            "-p",
            str(tmp_path),
            "-d",
            str(terraform_dir / "aws_s3_encryption_audit"),
        ],
    )
    assert caplog.record_tuples == [("c7n.iac", 30, "no policies found")]


@pytest.mark.skipif(
    os.environ.get('GITHUB_ACTIONS') is None,
    reason="runs in github actions as it requires network access for schema validation",
)
def test_cli_gitlab_sast_output(policy_env, tmp_path, debug_cli_runner):
    policy_env.write_tf(
        """
resource "aws_cloudwatch_log_group" "yada" {
  name = "Bar"
}
        """
    )
    policy_env.write_policy(
        {
            "name": "tag-required",
            "description": "tags are required on log groups",
            "metadata": {"url": "https://cloudcustodian.io", "severity": "high"},
            "resource": "terraform.aws_cloudwatch_log_group",
            "filters": [{"tags": "absent"}],
        }
    )
    runner = debug_cli_runner  # CliRunner()
    result = runner.invoke(
        cli.cli,
        [
            "run",
            "-p",
            str(tmp_path),
            "-d",
            str(tmp_path),
            "-o",
            "gitlab_sast",
            "--output-file",
            str(tmp_path / "output.json"),
        ],
    )
    report = json.loads((tmp_path / "output.json").read_text())
    result = jsonschema.validate(report, json.loads(urlopen(output.GitlabSAST.SCHEMA_FILE).read()))
    assert not result


@pytest.mark.skipif(
    os.environ.get('GITHUB_ACTIONS') is None,
    reason="runs in github actions as it requires network access for tf get",
)
def test_cli_output_rich_mod_resource_ref(tmp_path, debug_cli_runner):
    (tmp_path / "main.tf").write_text(DB_MODULE_TF)
    (tmp_path / "policy.json").write_text(
        json.dumps(
            {
                "policies": [
                    {
                        "name": "check-backup",
                        "resource": "terraform.aws_db_instance",
                        "filters": [{"backup_retention_period": 0}],
                    }
                ]
            }
        )
    )
    subprocess.check_call(args="terraform get", shell=True, cwd=tmp_path)

    runner = CliRunner()
    result = runner.invoke(cli.cli, ["run", "-p", str(tmp_path), "-d", str(tmp_path), "-o", "cli"])
    assert result.exit_code == 1
    assert "References:" in result.output
    assert 'module.db.module.db_instance.aws_db_instance.this[0]' in result.output


def test_cli_output_rich(tmp_path):
    write_output_test_policy(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        cli.cli,
        [
            "run",
            "-p",
            str(tmp_path),
            "-d",
            str(terraform_dir / "aws_s3_encryption_audit"),
            "-o",
            "cli",
        ],
    )
    assert result.exit_code == 1
    assert "Reason: a description\n" in result.output
    assert "1 failed 2 passed" in result.output


def test_cli_selection(tmp_path):
    write_output_test_policy(
        tmp_path,
        {
            "name": "check-flow",
            "resource": "terraform.aws_vpc",
            "filters": [{"tags.Env": "Dev"}],
        },
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.cli,
        [
            "run",
            "-p",
            str(tmp_path),
            "--filters",
            "type=aws_vpc",
            "--summary",
            "resource",
            "-d",
            str(terraform_dir / "vpc_flow_logs"),
            "-o",
            "cli",
        ],
    )

    assert result.exit_code == 1
    assert "Summary - By Resource" in result.output
    assert "1 failed 1 passed" in result.output
    assert "1 compliant of 2 total" in result.output


def test_cli_output_rich_resource_summary(tmp_path):
    write_output_test_policy(
        tmp_path,
        {
            "name": "check-flow",
            "resource": "terraform.aws_vpc",
            "filters": [{"tags.Env": "Dev"}],
        },
    )
    runner = CliRunner()
    result = runner.invoke(
        cli.cli,
        [
            "run",
            "-p",
            str(tmp_path),
            "--summary",
            "resource",
            "-d",
            str(terraform_dir / "vpc_flow_logs"),
            "-o",
            "cli",
        ],
    )
    assert result.exit_code == 1
    assert "Summary - By Resource" in result.output
    assert "1 failed 1 passed" in result.output
    assert "1 compliant of 5 total" in result.output


def test_cli_output_github(tmp_path):
    write_output_test_policy(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        cli.cli,
        [
            "run",
            "-p",
            str(tmp_path),
            "-d",
            str(terraform_dir / "aws_s3_encryption_audit"),
            "-o",
            "github",
        ],
    )
    assert result.exit_code == 1
    expected = (
        "::error file=tests/terraform/aws_s3_encryption_audit/main.tf,line=25,lineEnd=28,"
        "title=terraform.aws_s3_bucket - policy:check-bucket severity:unknown::a description"
    )
    assert expected in result.output


def test_cli_output_json_query(tmp_path):
    write_output_test_policy(tmp_path)

    runner = CliRunner()
    runner.invoke(
        cli.cli,
        [
            "run",
            "-p",
            str(tmp_path),
            "-d",
            str(terraform_dir / "aws_s3_encryption_audit"),
            "-o",
            "json",
            "--output-file",
            str(tmp_path / "output.json"),
            "--output-query",
            "[].file_path",
        ],
    )

    results = json.loads((tmp_path / "output.json").read_text())
    assert results == {
        "results": [
            "tests/terraform/aws_s3_encryption_audit/main.tf",
        ]
    }


def test_cli_output_json(tmp_path):
    write_output_test_policy(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        cli.cli,
        [
            "run",
            "-p",
            str(tmp_path),
            "-d",
            str(terraform_dir / "aws_s3_encryption_audit"),
            "-o",
            "json",
            "--output-file",
            str(tmp_path / "output.json"),
        ],
    )
    assert result.exit_code == 1

    results = json.loads((tmp_path / "output.json").read_text())
    assert "results" in results
    assert results["results"] == [
        {
            "code_block": [
                [25, 'resource "aws_s3_bucket" "example_c" {'],
                [26, "  bucket = " '"c7n-aws-s3-encryption-audit-test-c"'],
                [27, '  acl    = "private"'],
                [28, "}"],
            ],
            "file_line_end": 28,
            "file_line_start": 25,
            "file_path": "tests/terraform/aws_s3_encryption_audit/main.tf",
            "policy": {
                "filters": [{"server_side_encryption_configuration": "absent"}],
                "mode": {"type": "terraform-source"},
                "name": "check-bucket",
                "resource": "terraform.aws_s3_bucket",
                "description": "a description",
            },
            "resource": {
                "__tfmeta": {
                    "filename": "main.tf",
                    "label": "aws_s3_bucket",
                    "line_end": 28,
                    "line_start": 25,
                    "path": "aws_s3_bucket.example_c",
                    "src_dir": "tests/terraform/aws_s3_encryption_audit",
                    "type": "resource",
                },
                "acl": "private",
                "bucket": "c7n-aws-s3-encryption-audit-test-c",
                "c7n:MatchedFilters": ["server_side_encryption_configuration"],
                "id": ANY,
            },
        }
    ]


def test_policy_metadata(policy_env):
    policy_env.write_policy(
        {
            "name": "test-a",
            "resource": "terraform.aws_security_group",
            "title": "check for open ports",
            "description": "no global access",
            "metadata": {
                "category": "network",
                "severity": "high",
            },
        }
    )
    policy_env.write_policy(
        {
            "name": "test-b",
            "resource": "terraform.aws_security_group",
            "title": "check for open ports",
            "description": "no global access",
            "metadata": {
                "category": ["network", "security"],
                "severity": "high",
            },
        }
    )
    policies = list(policy_env.get_policies())
    md = core.PolicyMetadata(policies[0])
    assert md.provider == "terraform"
    assert md.display_category == "network"
    assert md.title == "terraform.aws_security_group - policy:test-a category:network severity:high"
    assert repr(md) == "<PolicyMetadata name:test-a resource:terraform.aws_security_group>"


def test_selection_parse(policy_env):
    selection = policy_env.get_selection(None)
    assert len(selection) == 0

    selection = policy_env.get_selection("type=aws_flog_log,aws_iam_*")
    assert selection.filters["type"] == ["aws_flog_log", "aws_iam_*"]

    selection = policy_env.get_selection("type=aws_flow_log severity=high")
    assert dict(selection.filters) == {
        "type": ["aws_flow_log"],
        "severity": ["high"],
    }

    # check some value errors
    with pytest.raises(ValueError) as err:
        policy_env.get_selection("cotegory=abc")
    assert "unsupported filter" in str(err.value)

    with pytest.raises(ValueError) as err:
        policy_env.get_selection("severity=check")
    assert "invalid severity" in str(err.value)

    with pytest.raises(ValueError) as err:
        policy_env.get_selection("xyz")
    assert "key=value pair missing" in str(err)


def test_selection_resource_filter(policy_env):
    selection = policy_env.get_selection("type=aws_vpc id=example")
    graph = policy_env.get_graph(terraform_dir / "vpc_flow_logs")
    (rtype, resources) = list(graph.get_resources_by_type("aws_flow_log"))[0]
    assert selection.filter_resources(rtype, resources) == []

    for rtype, resources in graph.get_resources_by_type():
        resources = selection.filter_resources(rtype, resources)
        if rtype != "aws_vpc":
            assert not resources
        else:
            assert len(resources) == 1
            break
    assert resources[0]["__tfmeta"]["path"] == "aws_vpc.example"


def test_selection_policy_invalid_values(policy_env):
    policy_env.write_policy(
        {
            "name": "test-a",
            "resource": "terraform.aws_vpc",
            "metadata": {"severity": "abc", "category": True},
        }
    )

    policy_env.write_policy(
        {
            "name": "test-b",
            "resource": "terraform.aws_vpc",
            "metadata": {"severity": ["abc"], "category": 1},
        }
    )

    policies = policy_env.get_policies()

    selection = policy_env.get_selection("severity=unknown")
    assert {p.name for p in selection.filter_policies(policies)} == {"test-a", "test-b"}

    selection = policy_env.get_selection("category=cost")
    assert {p.name for p in selection.filter_policies(policies)} == set()


def test_selection_policy_filter(policy_env):
    policy_env.write_policy(
        {
            "name": "test-a",
            "resource": "terraform.aws_vpc",
        }
    )
    policy_env.write_policy(
        {
            "name": "test-b",
            "resource": "terraform.aws_log_group",
            "metadata": {"severity": "high", "category": "encryption"},
        }
    )
    policy_env.write_policy(
        {
            "name": "test-c",
            "resource": "terraform.aws_ebs_volume",
            "metadata": {"severity": "high", "category": ["encryption", "cost"]},
        }
    )

    policies = policy_env.get_policies()

    selection = policy_env.get_selection("severity=low")
    assert {p.name for p in selection.filter_policies(policies)} == {
        "test-b",
        "test-c",
    }

    selection = policy_env.get_selection("severity=high,unknown")
    assert {p.name for p in selection.filter_policies(policies)} == {
        "test-a",
        "test-b",
        "test-c",
    }

    selection = policy_env.get_selection("category=cost")
    assert {p.name for p in selection.filter_policies(policies)} == {"test-c"}

    selection = policy_env.get_selection("policy=test-a")
    assert {p.name for p in selection.filter_policies(policies)} == {"test-a"}

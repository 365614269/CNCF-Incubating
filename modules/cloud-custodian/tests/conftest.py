# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import os
import re
import pytest

from distutils.util import strtobool
from .constants import ACCOUNT_ID

try:
    from .zpill import PillTest
    from c7n.testing import PyTestUtils, reset_session_cache
    from pytest_terraform.tf import LazyPluginCacheDir, LazyReplay
except ImportError: # noqa
    # docker tests run with minimial deps
    class PyTestUtils:
        pass

    class PillTest:
        pass

    class LazyReplay:
        pass

    class LazyPluginCacheDir:
        pass


pytest_plugins = ("pytest_recording",)

# If we have C7N_FUNCTIONAL make sure Replay is False otherwise enable Replay
LazyReplay.value = not strtobool(os.environ.get('C7N_FUNCTIONAL', 'no'))
LazyPluginCacheDir.value = '../.tfcache'


class TerraformAWSRewriteHooks:
    """ Local pytest plugin

    Work around to allow for dynamic registration of hooks based on plugin availability
    """
    def pytest_terraform_modify_state(self, tfstate):
        """ Sanitize functional testing account data """
        tfstate.update(re.sub(r'\b\d{12}\b', ACCOUNT_ID, str(tfstate)))


class CustodianAWSTesting(PyTestUtils, PillTest):
    """Pytest AWS Testing Fixture
    """


def pytest_configure(config):
    # Only register pytest-terraform hooks if the plugin is available
    if config.pluginmanager.hasplugin("terraform"):
        config.pluginmanager.register(TerraformAWSRewriteHooks())


@pytest.fixture(scope='function')
def test(request):
    test_utils = CustodianAWSTesting(request)
    test_utils.addCleanup(reset_session_cache)
    return test_utils

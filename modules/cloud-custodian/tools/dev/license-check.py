# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from importlib import metadata
import sys

accept = (
    'MIT',
    'BSD',
    'Apache License 2.0',
    'Apache 2.0',
    'MIT License',
    'Apache 2',
    'BSD License',
    'MPL 2.0',
    'BSD-3-Clause',
    'Apache-2.0',
    'Apache-2',
)

accept_classifiers = set(
    (
        'License :: OSI Approved',
        'License :: OSI Approved :: Python Software Foundation License',
        'License :: OSI Approved :: Apache Software License',
        'License :: OSI Approved :: MIT License',
        'License :: OSI Approved :: BSD License',
        'License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)',
        'License :: Public Domain'
        #    'License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)'
    )
)

whitelist_packages = set(
    (
        #
        # Deps with licenses that get flagged
        'pygit2',  # tools/c7n_policystream dep, GPL w/ Linking Exception
        'astroid',  # ci for codelint, LGPL-2.1
        'pylint',  # ci for codelint, GPL
        'semgrep',  # ci, LGPLv2
        'ldap3',  # mailer dependency, LGPL
        'sphinx-markdown-tables',  # docgen - GPL
        'docutils',  # docgen - couple of different licenses but bulk is public domain
        # 'chardet',  # requests dep - LPGL
        'websocket-client',  # c7n_kube dep - LGPL-2.1
        #
        # packages with bad metadata
        'applicationinsights',  # MIT
        'msal-extensions',  # MIT
        'protobuf',  # BSD-3-Clause
        'python-http-client',  # MIT
        'sendgrid',  # MIT
        'typed-ast',  # apache 2.0
        'starkbank-ecdsa',  # MIT
        'portalocker',  # PSF
    )
)


def main():
    seen = set()
    found = False
    for d in sorted(metadata.distributions(), key=lambda d: d.metadata['Name']):
        dname = d.metadata['Name']
        if dname in seen:
            continue
        if d.metadata['License'] in accept:
            continue
        if d.metadata['License'] is not None and ' or ' in d.metadata['License']:
            licenses = str(d.metadata['License']).split(' or ')
            if any(i in licenses for i in accept):
                continue

        classifiers = d.metadata.get_all('Classifier') or ()
        classifiers = [c for c in classifiers if c.startswith('License')]
        delta = set(classifiers).difference(accept_classifiers)
        if (delta or not classifiers) and dname not in whitelist_packages:
            found = True
            print(f"{dname}: {d.metadata['License']} {classifiers}")

        seen.add(dname)

    if found:
        sys.exit(1)


if __name__ == '__main__':
    main()

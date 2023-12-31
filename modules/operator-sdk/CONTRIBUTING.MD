# How to contribute

Operator SDK is Apache 2.0 licensed and accepts contributions via GitHub pull requests. This document outlines some of the conventions on commit message formatting, contact points for developers, and other resources to help get contributions into operator-sdk.

# Email and Chat

- Email: [operator-framework][operator_framework]  

## Getting started

- Fork the repository on GitHub
- See the [developer guide][developer-guide] for build instructions

## Reporting bugs and creating issues

Reporting bugs is one of the best ways to contribute. However, a good bug report has some very specific qualities, so please read over our short document on [reporting issues][reporting-issues] before submitting a bug report. This document might contain links to known issues, another good reason to take a look there before reporting a bug.

## Contribution flow

This is a rough outline of what a contributor's workflow looks like:

- Create a topic branch from where to base the contribution. This is usually master.
- Make commits of logical units.
- Make sure commit messages are in the proper format (see below).
- Push changes in a topic branch to a personal fork of the repository.
- Submit a pull request to operator-framework/operator-sdk.
- The PR must receive a LGTM from two maintainers found in the MAINTAINERS file.

Thanks for contributing!

### Code style

The coding style suggested by the Go community is used in operator-sdk. See the [style doc][golang-style-doc] for details.

Please follow this style to make operator-sdk easy to review, maintain and develop.

### Format of the commit message

We follow a rough convention for commit messages that is designed to answer two
questions: what changed and why. The subject line should feature the what and
the body of the commit should describe the why.

```
scripts: add the test-cluster command

this uses tmux to setup a test cluster that can easily be killed and started for debugging.

Fixes #38
```

The format can be described more formally as follows:

```
<subsystem>: <what changed>
<BLANK LINE>
<why this change was made>
<BLANK LINE>
<footer>
```

The first line is the subject and should be no longer than 70 characters, the second line is always blank, and other lines should be wrapped at 80 characters. This allows the message to be easier to read on GitHub as well as in various git tools.

## Documentation

Most contributions involve some sort of documentation. See our [doc contribution guidelines][doc-contrib] for details.

## Changelog

The operator-sdk maintains a changelog and most contributions should involve a changelog entry. See our [changelog contribution guidelines][changelog-contrib] for details.

[operator_framework]: https://groups.google.com/forum/#!forum/operator-framework
[developer-guide]: https://sdk.operatorframework.io/docs/contribution-guidelines/developer-guide/
[reporting-issues]: https://sdk.operatorframework.io/docs/contribution-guidelines/reporting-issues/
[golang-style-doc]: https://github.com/golang/go/wiki/CodeReviewComments
[doc-contrib]: https://sdk.operatorframework.io/docs/contribution-guidelines/documentation
[changelog-contrib]:https://master.sdk.operatorframework.io/docs/contribution-guidelines/changelog

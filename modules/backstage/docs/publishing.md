<!-- This is intentionally left out of the microsite, since it only applies to the main repo -->

## npm

npm packages are published through CI/CD in the
[`.github/workflows/deploy_packages.yml`](https://github.com/backstage/backstage/blob/master/.github/workflows/deploy_packages.yml)
workflow. Every commit that is merged to master will be checked for new versions
of all public packages, and any new versions will automatically be published to
npm.

### Creating a new release

Releases are handled by changesets and trigger whenever the "Version Packages"
PR is merged. This is typically done every Tuesday around noon CET.

## Next Line Release Process

- PR Checks: Ensure there are no outstanding PRs pending to be merged for this version. If there are any, reach out to maintainers and relevant owners of the affected code reminding them of the deadline for the release.
- [optional] Lock main branch
  - Lock the main branch to prevent any new merges.
  - Note: Admin rights are required to lock the branch. If you lack the necessary permissions, contact a core maintainer to perform this action on your behalf.
- Check [`Version Packages (next)` Pull Request](https://github.com/backstage/backstage/pulls?q=is%3Aopen+is%3Apr+in%3Atitle+%22Version+Packages+%28next%29%22)
  - Verify the version we are shipping is correct, by looking at the version packages PR title. It should be "Version Packages (next)"
  - Check [`.changeset/pre.json`](https://github.com/backstage/backstage/blob/master/.changeset/pre.json) if the `mode` is set to `pre`. If you encounter `mode: "exit"` or if it's not defined, it indicates a mainline release.
- Verify that there are no active/unfinished `sync_version-packages` actions running (https://github.com/backstage/backstage/actions/workflows/sync_version-packages.yml)
  - Locking the main branch will prevent new ones to be created, but be sure to check for running actions again after unlocking, since it may cause pending auto-merge PRs to be merged.
- Check [`Version Packages (next)` Pull Request](https://github.com/backstage/backstage/pulls?q=is%3Aopen+is%3Apr+in%3Atitle+%22Version+Packages+%28next%29%22) for sufficient approval to be merged
  - Check generated `changelog` in the changed files of the pull request under `docs/releases` to see if there are any unexpected major bumps e.g. by searching the file
  - Review & approve changes
  - Reach out to core maintainer to merge the pull request
  - Heads-up: The microsite building step can be skipped as long as the `prettier` task passes & everything else looks green

Merging the `Version Packages (next)` Pull Request will trigger the deployment workflows. Follow along the [deployment workflow](https://github.com/backstage/backstage/actions/workflows/deploy_packages.yml). If you notice flakiness (e.g. if the build is flaky or if the release step runs into an error with releasing to npm) just restart the workflow.

Congratulations on the release! There should be now a post in the [`#announcements` channel](https://discord.com/channels/687207715902193673/705123584468582400) in Discord linking to the release tag - check if links & tag look as expected. Finally unlock the main branch again. Merging PRs in master directly after release should be done with caution as it potential complicates fixing issues introduced in the release.

## Switching Release Modes

- To enter pre-release mode: `yarn changeset pre enter next` & create PR + merge changes
- To exit pre-release mode: `yarn changeset pre exit` & create PR + merge changes
  - Has to be done before the mainline release
- It's not time critical; Affects the next release happening

## Emergency Release Process

**This emergency release process is intended only for the Backstage
maintainers.**

Given one or more PRs towards master that we want to create a patch release for, run the following script from the repo root:

```bash
./scripts/patch-release-for-pr.js <pr-number> <pr-number-2> ...
```

Wait until the script has finished executing, at the end of the output you will find a link of the format `https://github.com/backstage/backstage/compare/patch/...`. Open this link in your browser to create a PR for the patch release. Finish the sentence "This release fixes an issue where..." and create the PR.

Once the PR has been approved and merged, the patch release will be automatically created. The patch release is complete when a notification has been posted to Discord in the `#announcements` channel. Keep an eye on "Deploy Packages" workflow and re-trigger if it fails. It is safe to re-trigger any part of this workflow, including the release step.

If the above process fails, you can fall back to the manual process documented below.

### Old Process

This is the old and manual process that we used before the patch script, provided here as a reference:

For this example we will be using the `@backstage/plugin-foo` package as an
example and assume that it is currently version `6.5.0` in the master branch.

In the event of a severe bug being introduced in version `6.5.0` of the
`@backstage/plugin-foo` released in the `v1.18.0` Backstage release, the following
process is used to release an emergency fix as version `6.5.1` in the patch release `v1.18.1`:

- [ ] Identify the release or releases that need to be patched. We should always
      patch the most recent major or minor main-line release if needed, which in this example
      would be `v1.18.0`. The fix may also need backporting to older major
      versions, in which case we will want to patch the main-line release just
      before the one that bumped the package to each new major version.
- [ ] Repeat the following steps for each release that needs to be patched:

  - [ ] Make sure a patch branch exists for the release that is being patched.
        If a patch already exists, reuse the existing branch. The branch **must
        always** be named exactly `patch/<release>`.

    ```bash
    git checkout v1.18.0
    git checkout -b patch/v1.18.0
    git push --set-upstream origin patch/v1.18.0
    ```

  - [ ] With the `patch/v1.18.0` branch as a base, create a new
        branch for your fix. This branch can be named anything, but the
        following naming pattern may be suitable:

    ```bash
    git checkout -b ${USER}/plugin-foo-v1.18.0-fix
    ```

  - [ ] Create a single commit that applies fix, nothing else.
  - [ ] Create a changeset for the affected package(s), then run `yarn release` in the root
        of the repo in order to convert your changeset into package version bumps and changelog entries.
        Commit these changes as a second `"Generated release"` commit.
  - [ ] Create PR towards the base branch (`patch/v1.18.0`) containing the two commits.
    - [ ] Add a PR body, it will be used as the release description. Typically something like "This release fixes ...".
  - [ ] Review/Merge the PR into `patch/v1.18.0`. This will automatically trigger a release.

- [ ] Look up the new version of our package in the patch PR as well as the new release
      version, these can be found in the package `package.json` and the root `package.json`, and
      will in this case be `6.5.1` and `v1.18.1`. You will need these versions later.
- [ ] Make sure you have the latest versions of the patch branch fetched, after merging the PR: `git fetch`.
- [ ] Once fixes have been created for each release, the fix should be applied to the
      master branch as well. Create a PR that contains the following:

  - [ ] The fix, which you can likely cherry-pick from your patch branch: `git cherry-pick origin/patch/v1.18.0^`
  - [ ] An updated `CHANGELOG.md` of all patched packages from the tip of the patch branch, `git checkout origin/patch/v1.18.0 -- {packages,plugins}/*/CHANGELOG.md`. Note that if the patch happens after any next-line releases you'll need to restore those entries in the changelog, placing the patch release entry beneath any next-line release entries.
  - [ ] A changeset with the message "Applied the fix from version `6.5.1` of this package, which is part of the `v1.18.1` release of Backstage."

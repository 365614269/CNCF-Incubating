# @backstage/plugin-auth-backend-module-microsoft-provider

## 0.1.2

### Patch Changes

- a3236ad0ca: Fix link to the repository in `README.md`.
- 3979524c74: Added support for specifying a domain hint on the Microsoft authentication provider configuration.
- fde212dd10: Re-add the missing profile photo
  as well as access token retrieval for foreign scopes.

  Additionally, we switch from previously 48x48 to 96x96
  which is the size used at the profile card.

- 5aeb14f035: Correctly mark the client secret in configuration as secret
- 2817115d09: Removed `prompt=consent` from start method to fix #20641
- Updated dependencies
  - @backstage/backend-common@0.19.9
  - @backstage/backend-plugin-api@0.6.7
  - @backstage/plugin-auth-node@0.4.1

## 0.1.2-next.2

### Patch Changes

- [#20706](https://github.com/backstage/backstage/pull/20706) [`fde212dd10`](https://github.com/backstage/backstage/commit/fde212dd106e507c4a808e5ed8213e29d7338420) Thanks [@pjungermann](https://github.com/pjungermann)! - Re-add the missing profile photo
  as well as access token retrieval for foreign scopes.

  Additionally, we switch from previously 48x48 to 96x96
  which is the size used at the profile card.

- Updated dependencies
  - @backstage/backend-plugin-api@0.6.7-next.2
  - @backstage/backend-common@0.19.9-next.2
  - @backstage/plugin-auth-node@0.4.1-next.2

## 0.1.2-next.1

### Patch Changes

- 3979524c74: Added support for specifying a domain hint on the Microsoft authentication provider configuration.
- 5aeb14f035: Correctly mark the client secret in configuration as secret
- Updated dependencies
  - @backstage/backend-common@0.19.9-next.1
  - @backstage/plugin-auth-node@0.4.1-next.1
  - @backstage/backend-plugin-api@0.6.7-next.1

## 0.1.2-next.0

### Patch Changes

- 2817115d09: Removed `prompt=consent` from start method to fix #20641
- Updated dependencies
  - @backstage/backend-common@0.19.9-next.0
  - @backstage/backend-plugin-api@0.6.7-next.0
  - @backstage/plugin-auth-node@0.4.1-next.0

## 0.1.0

### Minor Changes

- 2d8f7e82c1: Migrated the Microsoft auth provider to new `@backstage/plugin-auth-backend-module-microsoft-provider` module package.

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.19.8
  - @backstage/plugin-auth-node@0.4.0
  - @backstage/backend-plugin-api@0.6.6

## 0.1.0-next.0

### Minor Changes

- 2d8f7e82c1: Migrated the Microsoft auth provider to new `@backstage/plugin-auth-backend-module-microsoft-provider` module package.

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.19.8-next.2
  - @backstage/plugin-auth-node@0.4.0-next.2
  - @backstage/backend-plugin-api@0.6.6-next.2

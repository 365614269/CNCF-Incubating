# @backstage/frontend-app-api

## 0.4.0-next.3

### Patch Changes

- Updated dependencies
  - @backstage/core-components@0.13.9-next.3
  - @backstage/config@1.1.1
  - @backstage/core-app-api@1.11.2-next.1
  - @backstage/core-plugin-api@1.8.1-next.1
  - @backstage/frontend-plugin-api@0.4.0-next.3
  - @backstage/theme@0.5.0-next.1
  - @backstage/types@1.1.1
  - @backstage/version-bridge@1.0.7

## 0.4.0-next.2

### Minor Changes

- ea06590: The app no longer provides the `AppContext` from `@backstage/core-plugin-api`. Components that require this context to be available should use the `compatWrapper` helper from `@backstage/core-compat-api`.

### Patch Changes

- aeb8008: Add support for translation extensions.
- b7adf24: Use the new plugin type for error boundary components.
- 8f5d6c1: Updates to match the new extension input wrapping.
- cb4197a: Forward ` node`` instead of  `extensionId` to resolved extension inputs.
- 8837a96: Updates to match the introduction of `ExtensionDefinition` and new extension ID naming patterns.
- Updated dependencies
  - @backstage/frontend-plugin-api@0.4.0-next.2
  - @backstage/theme@0.5.0-next.1
  - @backstage/config@1.1.1
  - @backstage/core-app-api@1.11.2-next.1
  - @backstage/core-components@0.13.9-next.2
  - @backstage/core-plugin-api@1.8.1-next.1
  - @backstage/types@1.1.1
  - @backstage/version-bridge@1.0.7

## 0.4.0-next.1

### Minor Changes

- e539735435: Updated core extension structure to make space for the sign-in page by adding `core.router`.

### Patch Changes

- 5eb6b8a7bc: Added the nav logo extension for customization of sidebar logo
- 1f12fb762c: Create a core components extension that allows adopters to override core app components such as `Progress`, `BootErrorPage`, `NotFoundErrorPage` and `ErrorBoundaryFallback`.
- 59709286b3: Collect and register feature flags from plugins and extension overrides.
- f27ee7d937: Migrate analytics route tracker component.
- a5a04739e1: Updates to provide `node` to extension factories instead of `id` and `source`.
- Updated dependencies
  - @backstage/frontend-plugin-api@0.4.0-next.1
  - @backstage/core-components@0.13.9-next.1
  - @backstage/core-plugin-api@1.8.1-next.1
  - @backstage/core-app-api@1.11.2-next.1
  - @backstage/config@1.1.1
  - @backstage/theme@0.5.0-next.0
  - @backstage/types@1.1.1
  - @backstage/version-bridge@1.0.7

## 0.3.1-next.0

### Patch Changes

- 60d6eb544e: Removed `@backstage/plugin-graphiql` dependency.
- 9ad4039efa: Bringing over apis from core-plugin-api
- b8cb7804c8: Added `createSpecializedApp`, which is a synchronous version of `createApp` where config and features already need to be loaded.
- Updated dependencies
  - @backstage/core-plugin-api@1.8.1-next.0
  - @backstage/core-components@0.13.9-next.0
  - @backstage/theme@0.5.0-next.0
  - @backstage/frontend-plugin-api@0.3.1-next.0
  - @backstage/core-app-api@1.11.2-next.0
  - @backstage/config@1.1.1
  - @backstage/types@1.1.1
  - @backstage/version-bridge@1.0.7

## 0.3.0

### Minor Changes

- 68fc9dc60e: Added the ability to configure bound routes through `app.routes.bindings`. The routing system used by `createApp` has been replaced by one that only supports route refs of the new format from `@backstage/frontend-plugin-api`. The requirement for route refs to have the same ID as their associated extension has been removed.

### Patch Changes

- e28d379e32: Refactor internal extension instance system into an app graph.
- fdc348d5d3: The options parameter of `createApp` is now optional.
- 6c2b872153: Add official support for React 18.
- dc613f9bcf: Updated `app.extensions` configuration schema.
- 733bd95746: Implement new `AppTreeApi`
- 685a4c8901: Installed features are now deduplicated both by reference and ID when available. Features passed to `createApp` now override both discovered and loaded features.
- fa28d4e6df: No longer throw error on invalid input if the child is disabled.
- bb98953cb9: Register default implementation for the `Translation API` on the new `createApp`.
- fe6d09953d: Fix for app node output IDs not being serialized correctly.
- 77f009b35d: Internal updates to match changes in the experimental `@backstage/frontend-plugin-api`.
- 4d6fa921db: Internal refactor to rename the app graph to app tree
- Updated dependencies
  - @backstage/core-components@0.13.8
  - @backstage/frontend-plugin-api@0.3.0
  - @backstage/plugin-graphiql@0.3.0
  - @backstage/core-plugin-api@1.8.0
  - @backstage/version-bridge@1.0.7
  - @backstage/core-app-api@1.11.1
  - @backstage/theme@0.4.4
  - @backstage/config@1.1.1
  - @backstage/types@1.1.1

## 0.3.0-next.2

### Patch Changes

- [#20999](https://github.com/backstage/backstage/pull/20999) [`fdc348d5d3`](https://github.com/backstage/backstage/commit/fdc348d5d30a98b52d8a756daba29d616418da93) Thanks [@Rugvip](https://github.com/Rugvip)! - The options parameter of `createApp` is now optional.

- [#20888](https://github.com/backstage/backstage/pull/20888) [`733bd95746`](https://github.com/backstage/backstage/commit/733bd95746b99ad8cdb4a7b87e8dc3e16d3b764a) Thanks [@Rugvip](https://github.com/Rugvip)! - Implement new `AppTreeApi`

- [#20999](https://github.com/backstage/backstage/pull/20999) [`fa28d4e6df`](https://github.com/backstage/backstage/commit/fa28d4e6dfcbee2bc8695b7b24289a401df96acd) Thanks [@Rugvip](https://github.com/Rugvip)! - No longer throw error on invalid input if the child is disabled.

- Updated dependencies
  - @backstage/core-components@0.13.8-next.2
  - @backstage/frontend-plugin-api@0.3.0-next.2
  - @backstage/plugin-graphiql@0.3.0-next.2

## 0.3.0-next.1

### Patch Changes

- fe6d09953d: Fix for app node output IDs not being serialized correctly.
- 77f009b35d: Internal updates to match changes in the experimental `@backstage/frontend-plugin-api`.
- 4d6fa921db: Internal refactor to rename the app graph to app tree
- Updated dependencies
  - @backstage/frontend-plugin-api@0.3.0-next.1
  - @backstage/plugin-graphiql@0.3.0-next.1
  - @backstage/core-components@0.13.8-next.1
  - @backstage/config@1.1.1
  - @backstage/core-app-api@1.11.1-next.0
  - @backstage/core-plugin-api@1.8.0-next.0
  - @backstage/theme@0.4.4-next.0
  - @backstage/types@1.1.1
  - @backstage/version-bridge@1.0.7-next.0

## 0.3.0-next.0

### Minor Changes

- 68fc9dc60e: Added the ability to configure bound routes through `app.routes.bindings`. The routing system used by `createApp` has been replaced by one that only supports route refs of the new format from `@backstage/frontend-plugin-api`. The requirement for route refs to have the same ID as their associated extension has been removed.

### Patch Changes

- e28d379e32: Refactor internal extension instance system into an app graph.
- 6c2b872153: Add official support for React 18.
- dc613f9bcf: Updated `app.extensions` configuration schema.
- 685a4c8901: Installed features are now deduplicated both by reference and ID when available. Features passed to `createApp` now override both discovered and loaded features.
- bb98953cb9: Register default implementation for the `Translation API` on the new `createApp`.
- Updated dependencies
  - @backstage/core-components@0.13.7-next.0
  - @backstage/frontend-plugin-api@0.3.0-next.0
  - @backstage/plugin-graphiql@0.3.0-next.0
  - @backstage/core-plugin-api@1.8.0-next.0
  - @backstage/version-bridge@1.0.7-next.0
  - @backstage/core-app-api@1.11.1-next.0
  - @backstage/theme@0.4.4-next.0
  - @backstage/config@1.1.1
  - @backstage/types@1.1.1

## 0.2.0

### Minor Changes

- 4461d87d5a: Removed support for the new `useRouteRef`.
- 9d03dfe5e3: The `createApp` config option has been replaced by a new `configLoader` option. There is now also a `pluginLoader` option that can be used to dynamically load plugins into the app.
- d7c5d80c57: The hidden `'root'` extension has been removed and has instead been made an input of the `'core'` extension. The checks for rejecting configuration of the `'root'` extension to rejects configuration of the `'core'` extension instead.
- d920b8c343: Added support for installing `ExtensionOverrides` via `createApp` options. As part of this change the `plugins` option has been renamed to `features`, and the `pluginLoader` has been renamed to `featureLoader`.

### Patch Changes

- 322bbcae24: Internal update for removal of experimental plugin configuration API.
- f78ac58f88: Filters for discovered packages are now also applied at runtime. This makes it possible to disable packages through the `app.experimental.packages` config at runtime.
- 68ffb9e67d: The app will now reject any extensions that attach to nonexistent inputs.
- 5072824817: Implement `toString()` and `toJSON()` for extension instances.
- 1e60a9c3a5: Fixed an issue preventing the routing system to match subroutes
- 52366db5b3: Make themes configurable through extensions, and switched default themes to use extensions instead.
- 2ecd33618a: Added the `bindRoutes` option to `createApp`.
- e5a2956dd2: Register default api implementations when creating declarative integrated apps.
- 9a1fce352e: Updated dependency `@testing-library/jest-dom` to `^6.0.0`.
- 06432f900c: Updates for `at` -> `attachTo` refactor.
- 1718ec75b7: Added support for the existing routing system.
- 66d51a4827: Prevents root extension override and duplicated plugin extensions.
- Updated dependencies
  - @backstage/frontend-plugin-api@0.2.0
  - @backstage/core-app-api@1.11.0
  - @backstage/core-plugin-api@1.7.0
  - @backstage/core-components@0.13.6
  - @backstage/plugin-graphiql@0.2.55
  - @backstage/version-bridge@1.0.6
  - @backstage/theme@0.4.3
  - @backstage/config@1.1.1
  - @backstage/types@1.1.1

## 0.2.0-next.2

### Minor Changes

- 4461d87d5a: Removed support for the new `useRouteRef`.

### Patch Changes

- 5072824817: Implement `toString()` and `toJSON()` for extension instances.
- 06432f900c: Updates for `at` -> `attachTo` refactor.
- 1718ec75b7: Added support for the existing routing system.
- Updated dependencies
  - @backstage/frontend-plugin-api@0.2.0-next.2
  - @backstage/core-app-api@1.11.0-next.2
  - @backstage/core-components@0.13.6-next.2
  - @backstage/core-plugin-api@1.7.0-next.1
  - @backstage/plugin-graphiql@0.2.55-next.2
  - @backstage/theme@0.4.3-next.0
  - @backstage/config@1.1.1-next.0
  - @backstage/types@1.1.1
  - @backstage/version-bridge@1.0.5

## 0.2.0-next.1

### Patch Changes

- 52366db5b3: Make themes configurable through extensions, and switched default themes to use extensions instead.
- e5a2956dd2: Register default api implementations when creating declarative integrated apps.
- Updated dependencies
  - @backstage/frontend-plugin-api@0.1.1-next.1
  - @backstage/core-components@0.13.6-next.1
  - @backstage/core-app-api@1.10.1-next.1
  - @backstage/plugin-graphiql@0.2.55-next.1
  - @backstage/core-plugin-api@1.7.0-next.0
  - @backstage/config@1.1.0
  - @backstage/theme@0.4.2
  - @backstage/types@1.1.1

## 0.2.0-next.0

### Minor Changes

- 9d03dfe5e3: The `createApp` config option has been replaced by a new `configLoader` option. There is now also a `pluginLoader` option that can be used to dynamically load plugins into the app.

### Patch Changes

- 322bbcae24: Internal update for removal of experimental plugin configuration API.
- 66d51a4827: Prevents root extension override and duplicated plugin extensions.
- Updated dependencies
  - @backstage/core-plugin-api@1.7.0-next.0
  - @backstage/core-components@0.13.6-next.0
  - @backstage/frontend-plugin-api@0.1.1-next.0
  - @backstage/config@1.1.0
  - @backstage/core-app-api@1.10.1-next.0
  - @backstage/plugin-graphiql@0.2.55-next.0
  - @backstage/types@1.1.1

## 0.1.0

### Minor Changes

- 628ca7e458e4: Initial release

### Patch Changes

- Updated dependencies
  - @backstage/plugin-graphiql@0.2.54
  - @backstage/frontend-plugin-api@0.1.0
  - @backstage/core-components@0.13.5
  - @backstage/config@1.1.0
  - @backstage/core-app-api@1.10.0
  - @backstage/core-plugin-api@1.6.0
  - @backstage/types@1.1.1

## 0.1.0-next.0

### Minor Changes

- 628ca7e458e4: Initial release

### Patch Changes

- Updated dependencies
  - @backstage/frontend-plugin-api@0.1.0-next.0
  - @backstage/plugin-graphiql@0.2.54-next.3
  - @backstage/config@1.1.0-next.2
  - @backstage/core-app-api@1.10.0-next.3
  - @backstage/core-components@0.13.5-next.3
  - @backstage/core-plugin-api@1.6.0-next.3
  - @backstage/types@1.1.1-next.0

## 0.0.1-next.1

### Patch Changes

- Updated dependencies
  - @backstage/core-plugin-api@1.6.0-next.2
  - @backstage/plugin-graphiql@0.2.54-next.2
  - @backstage/config@1.1.0-next.1
  - @backstage/frontend-plugin-api@0.0.1-next.0
  - @backstage/types@1.1.0

## 0.0.1-next.0

### Patch Changes

- Updated dependencies
  - @backstage/config@1.1.0-next.0
  - @backstage/plugin-graphiql@0.2.54-next.1
  - @backstage/frontend-plugin-api@0.0.0
  - @backstage/types@1.1.0

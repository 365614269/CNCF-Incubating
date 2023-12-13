# @backstage/frontend-plugin-api

## 0.4.0-next.3

### Patch Changes

- Updated dependencies
  - @backstage/core-components@0.13.9-next.3
  - @backstage/config@1.1.1
  - @backstage/core-plugin-api@1.8.1-next.1
  - @backstage/types@1.1.1
  - @backstage/version-bridge@1.0.7

## 0.4.0-next.2

### Minor Changes

- 8f5d6c1: Extension inputs are now wrapped into an additional object when passed to the extension factory, with the previous values being available at the `output` property. The `ExtensionInputValues` type has also been replaced by `ResolvedExtensionInputs`.
- 8837a96: **BREAKING**: This version changes how extensions are created and how their IDs are determined. The `createExtension` function now accepts `kind`, `namespace` and `name` instead of `id`. All of the new options are optional, and are used to construct the final extension ID. By convention extension creators should set the `kind` to match their own name, for example `createNavItemExtension` sets the kind `nav-item`.

  The `createExtension` function as well as all extension creators now also return an `ExtensionDefinition` rather than an `Extension`, which in turn needs to be passed to `createPlugin` or `createExtensionOverrides` to be used.

### Patch Changes

- b7adf24: Update alpha component ref type to be more specific than any, delete boot page component and use new plugin type for error boundary component extensions.
- 73246ec: Added translation APIs as well as `createTranslationExtension`.
- cb4197a: Forward ` node`` instead of  `extensionId` to resolved extension inputs.
- Updated dependencies
  - @backstage/config@1.1.1
  - @backstage/core-components@0.13.9-next.2
  - @backstage/core-plugin-api@1.8.1-next.1
  - @backstage/types@1.1.1
  - @backstage/version-bridge@1.0.7

## 0.4.0-next.1

### Minor Changes

- a5a04739e1: The extension `factory` function now longer receives `id` or `source`, but instead now provides the extension's `AppNode` as `node`. The `ExtensionBoundary` component has also been updated to receive a `node` prop rather than `id` and `source`.

### Patch Changes

- 5eb6b8a7bc: Added the nav logo extension for customization of sidebar logo
- 1f12fb762c: Create factories for overriding default core components extensions.
- 59709286b3: Add feature flags to plugins and extension overrides.
- e539735435: Added `createSignInPageExtension`.
- f27ee7d937: Migrate analytics api and context files.
- Updated dependencies
  - @backstage/core-components@0.13.9-next.1
  - @backstage/core-plugin-api@1.8.1-next.1
  - @backstage/config@1.1.1
  - @backstage/types@1.1.1
  - @backstage/version-bridge@1.0.7

## 0.3.1-next.0

### Patch Changes

- Updated dependencies
  - @backstage/core-plugin-api@1.8.1-next.0
  - @backstage/core-components@0.13.9-next.0
  - @backstage/config@1.1.1
  - @backstage/types@1.1.1
  - @backstage/version-bridge@1.0.7

## 0.3.0

### Minor Changes

- 68fc9dc60e: Added `RouteRef`, `SubRouteRef`, `ExternalRouteRef`, and related types. All exports from this package that previously relied on the types with the same name from `@backstage/core-plugin-api` now use the new types instead. To convert and existing legacy route ref to be compatible with the APIs from this package, use the `convertLegacyRouteRef` utility from `@backstage/core-plugin-api/alpha`.
- 77f009b35d: Extensions now return their output from the factory function rather than calling `bind(...)`.

### Patch Changes

- 6c2b872153: Add official support for React 18.
- 733bd95746: Add new `AppTreeApi`.
- 6af88a05ff: Improve the extension boundary component and create a default extension suspense component.
- Updated dependencies
  - @backstage/core-components@0.13.8
  - @backstage/core-plugin-api@1.8.0
  - @backstage/version-bridge@1.0.7
  - @backstage/types@1.1.1

## 0.3.0-next.2

### Patch Changes

- [#20888](https://github.com/backstage/backstage/pull/20888) [`733bd95746`](https://github.com/backstage/backstage/commit/733bd95746b99ad8cdb4a7b87e8dc3e16d3b764a) Thanks [@Rugvip](https://github.com/Rugvip)! - Add new `AppTreeApi`.

- Updated dependencies
  - @backstage/core-components@0.13.8-next.2

## 0.3.0-next.1

### Minor Changes

- 77f009b35d: Extensions now return their output from the factory function rather than calling `bind(...)`.

### Patch Changes

- Updated dependencies
  - @backstage/core-components@0.13.8-next.1
  - @backstage/core-plugin-api@1.8.0-next.0
  - @backstage/types@1.1.1
  - @backstage/version-bridge@1.0.7-next.0

## 0.3.0-next.0

### Minor Changes

- 68fc9dc60e: Added `RouteRef`, `SubRouteRef`, `ExternalRouteRef`, and related types. All exports from this package that previously relied on the types with the same name from `@backstage/core-plugin-api` now use the new types instead. To convert and existing legacy route ref to be compatible with the APIs from this package, use the `convertLegacyRouteRef` utility from `@backstage/core-plugin-api/alpha`.

### Patch Changes

- 6c2b872153: Add official support for React 18.
- 6af88a05ff: Improve the extension boundary component and create a default extension suspense component.
- Updated dependencies
  - @backstage/core-components@0.13.7-next.0
  - @backstage/core-plugin-api@1.8.0-next.0
  - @backstage/version-bridge@1.0.7-next.0
  - @backstage/types@1.1.1

## 0.2.0

### Minor Changes

- 06432f900c: Extension attachment point is now configured via `attachTo: { id, input }` instead of `at: 'id/input'`.
- 4461d87d5a: Removed support for the new `useRouteRef`.

### Patch Changes

- d3a37f55c0: Add support for `SidebarGroup` on the sidebar item extension.
- 2ecd33618a: Plugins can now be assigned `routes` and `externalRoutes` when created.
- 9a1fce352e: Updated dependency `@testing-library/jest-dom` to `^6.0.0`.
- c1e9ca6500: Added `createExtensionOverrides` which can be used to install a collection of extensions in an app that will replace any existing ones.
- 52366db5b3: Added `createThemeExtension` and `coreExtensionData.theme`.
- Updated dependencies
  - @backstage/core-plugin-api@1.7.0
  - @backstage/types@1.1.1

## 0.2.0-next.2

### Minor Changes

- 06432f900c: Extension attachment point is now configured via `attachTo: { id, input }` instead of `at: 'id/input'`.
- 4461d87d5a: Removed support for the new `useRouteRef`.

### Patch Changes

- Updated dependencies
  - @backstage/core-plugin-api@1.7.0-next.1
  - @backstage/types@1.1.1

## 0.1.1-next.1

### Patch Changes

- d3a37f55c0: Add support for `SidebarGroup` on the sidebar item extension.
- 52366db5b3: Added `createThemeExtension` and `coreExtensionData.theme`.
- Updated dependencies
  - @backstage/core-plugin-api@1.7.0-next.0
  - @backstage/types@1.1.1

## 0.1.1-next.0

### Patch Changes

- Updated dependencies
  - @backstage/core-plugin-api@1.7.0-next.0
  - @backstage/types@1.1.1

## 0.1.0

### Minor Changes

- 628ca7e458e4: Initial release

### Patch Changes

- Updated dependencies
  - @backstage/core-plugin-api@1.6.0
  - @backstage/types@1.1.1

## 0.1.0-next.0

### Minor Changes

- 628ca7e458e4: Initial release

### Patch Changes

- Updated dependencies
  - @backstage/core-plugin-api@1.6.0-next.3
  - @backstage/types@1.1.1-next.0

## 0.0.1-next.0

### Patch Changes

- Updated dependencies
  - @backstage/core-plugin-api@1.6.0-next.2
  - @backstage/types@1.1.0

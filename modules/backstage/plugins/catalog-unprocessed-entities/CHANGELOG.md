# @backstage/plugin-catalog-unprocessed-entities

## 0.1.2-next.0

### Patch Changes

- Updated dependencies
  - @backstage/core-components@0.13.4-next.0
  - @backstage/core-plugin-api@1.5.3
  - @backstage/catalog-model@1.4.1
  - @backstage/errors@1.2.1
  - @backstage/theme@0.4.1

## 0.1.1

### Patch Changes

- 2c4869473155: The Catalog Unprocessed Entities plugin can now be integrated as a tab within the DevTools plugin

  - Added an export for `UnprocessedEntitiesContent`
  - Updated the `README` with images of the features
  - Adjusted the styles to fill in the available space
  - Set the table page size to 20 as 40 was causing errors in the browser console

- 57585d89f926: Export some types and API items. This allows people to call the API from different places with the ApiRef, as well
  as completely customize the client if required. Check the [README.md](https://github.com/backstage/backstage/blob/master/plugins/catalog-unprocessed-entities/README.md) to
  note what needs to be added in order to use the new `catalogUnprocessedEntitiesApiRef` exported function.
- a8fa79ccc105: Fix and improve documentation for the unprocessed entities modules.
- 267396f45bd0: Corrected the installation instructions.
- 7a9c8a9cd0ce: Fixed spacing for success message
- e6f50426333b: update some peer dependencies to silence yarn install
- 77b408fad872: install command points to correct package name
- Updated dependencies
  - @backstage/theme@0.4.1
  - @backstage/errors@1.2.1
  - @backstage/core-components@0.13.3
  - @backstage/core-plugin-api@1.5.3
  - @backstage/catalog-model@1.4.1

## 0.1.1-next.2

### Patch Changes

- Updated dependencies
  - @backstage/theme@0.4.1-next.1
  - @backstage/core-plugin-api@1.5.3-next.1
  - @backstage/core-components@0.13.3-next.2
  - @backstage/catalog-model@1.4.1-next.0
  - @backstage/errors@1.2.1-next.0

## 0.1.1-next.1

### Patch Changes

- 267396f45bd0: Corrected the installation instructions.
- 7a9c8a9cd0ce: Fixed spacing for success message
- 77b408fad872: install command points to correct package name
- Updated dependencies
  - @backstage/theme@0.4.1-next.0
  - @backstage/core-components@0.13.3-next.1
  - @backstage/core-plugin-api@1.5.3-next.0

## 0.1.1-next.0

### Patch Changes

- 2c4869473155: The Catalog Unprocessed Entities plugin can now be integrated as a tab within the DevTools plugin

  - Added an export for `UnprocessedEntitiesContent`
  - Updated the `README` with images of the features
  - Adjusted the styles to fill in the available space
  - Set the table page size to 20 as 40 was causing errors in the browser console

- 57585d89f926: Export some types and API items. This allows people to call the API from different places with the ApiRef, as well
  as completely customize the client if required. Check the [README.md](https://github.com/backstage/backstage/blob/master/plugins/catalog-unprocessed-entities/README.md) to
  note what needs to be added in order to use the new `catalogUnprocessedEntitiesApiRef` exported function.
- a8fa79ccc105: Fix and improve documentation for the unprocessed entities modules.
- Updated dependencies
  - @backstage/errors@1.2.1-next.0
  - @backstage/core-components@0.13.3-next.0
  - @backstage/catalog-model@1.4.1-next.0
  - @backstage/core-plugin-api@1.5.2
  - @backstage/theme@0.4.0

## 0.1.0

### Minor Changes

- d44fcd9829c2: Added a new plugin to expose entities which are unprocessed or have errors processing

### Patch Changes

- 493eab8c577f: Use FetchApi instead of native fetch
- Updated dependencies
  - @backstage/core-plugin-api@1.5.2
  - @backstage/core-components@0.13.2
  - @backstage/theme@0.4.0
  - @backstage/catalog-model@1.4.0
  - @backstage/errors@1.2.0

## 0.1.0-next.2

### Patch Changes

- Updated dependencies
  - @backstage/core-components@0.13.2-next.3
  - @backstage/catalog-model@1.4.0-next.1
  - @backstage/core-plugin-api@1.5.2-next.0
  - @backstage/errors@1.2.0-next.0
  - @backstage/theme@0.4.0-next.1

## 0.1.0-next.1

### Patch Changes

- Updated dependencies
  - @backstage/theme@0.4.0-next.1
  - @backstage/core-components@0.13.2-next.2
  - @backstage/core-plugin-api@1.5.2-next.0

## 0.1.0-next.0

### Minor Changes

- d44fcd9829c2: Added a new plugin to expose entities which are unprocessed or have errors processing

### Patch Changes

- Updated dependencies
  - @backstage/errors@1.2.0-next.0
  - @backstage/core-components@0.13.2-next.1
  - @backstage/catalog-model@1.4.0-next.0
  - @backstage/core-plugin-api@1.5.2-next.0
  - @backstage/theme@0.4.0-next.0

# @backstage/plugin-search-backend-module-explore

## 0.1.11

### Patch Changes

- Updated dependencies
  - @backstage/plugin-search-backend-node@1.2.11
  - @backstage/backend-common@0.19.9
  - @backstage/backend-plugin-api@0.6.7
  - @backstage/backend-tasks@0.5.12
  - @backstage/config@1.1.1
  - @backstage/plugin-explore-common@0.0.2
  - @backstage/plugin-search-common@1.2.8

## 0.1.11-next.2

### Patch Changes

- Updated dependencies
  - @backstage/backend-plugin-api@0.6.7-next.2
  - @backstage/backend-common@0.19.9-next.2
  - @backstage/backend-tasks@0.5.12-next.2
  - @backstage/plugin-search-backend-node@1.2.11-next.2

## 0.1.11-next.1

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.19.9-next.1
  - @backstage/backend-tasks@0.5.12-next.1
  - @backstage/plugin-search-backend-node@1.2.11-next.1
  - @backstage/backend-plugin-api@0.6.7-next.1
  - @backstage/config@1.1.1
  - @backstage/plugin-explore-common@0.0.2
  - @backstage/plugin-search-common@1.2.7

## 0.1.11-next.0

### Patch Changes

- Updated dependencies
  - @backstage/plugin-search-backend-node@1.2.11-next.0
  - @backstage/backend-common@0.19.9-next.0
  - @backstage/backend-plugin-api@0.6.7-next.0
  - @backstage/backend-tasks@0.5.12-next.0
  - @backstage/config@1.1.1
  - @backstage/plugin-explore-common@0.0.2
  - @backstage/plugin-search-common@1.2.7

## 0.1.10

### Patch Changes

- Updated dependencies
  - @backstage/backend-tasks@0.5.11
  - @backstage/backend-common@0.19.8
  - @backstage/backend-plugin-api@0.6.6
  - @backstage/plugin-search-backend-node@1.2.10
  - @backstage/config@1.1.1
  - @backstage/plugin-explore-common@0.0.2
  - @backstage/plugin-search-common@1.2.7

## 0.1.10-next.2

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.19.8-next.2
  - @backstage/backend-tasks@0.5.11-next.2
  - @backstage/plugin-search-backend-node@1.2.10-next.2
  - @backstage/backend-plugin-api@0.6.6-next.2
  - @backstage/config@1.1.1-next.0
  - @backstage/plugin-explore-common@0.0.2
  - @backstage/plugin-search-common@1.2.7-next.0

## 0.1.9-next.1

### Patch Changes

- Updated dependencies
  - @backstage/backend-tasks@0.5.10-next.1
  - @backstage/backend-common@0.19.7-next.1
  - @backstage/backend-plugin-api@0.6.5-next.1
  - @backstage/plugin-search-backend-node@1.2.9-next.1
  - @backstage/config@1.1.0
  - @backstage/plugin-explore-common@0.0.2
  - @backstage/plugin-search-common@1.2.6

## 0.1.9-next.0

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.19.7-next.0
  - @backstage/config@1.1.0
  - @backstage/backend-plugin-api@0.6.5-next.0
  - @backstage/backend-tasks@0.5.10-next.0
  - @backstage/plugin-explore-common@0.0.2
  - @backstage/plugin-search-backend-node@1.2.9-next.0
  - @backstage/plugin-search-common@1.2.6

## 0.1.7

### Patch Changes

- 71114ac50e02: The export for the new backend system has been moved to be the `default` export.

  For example, if you are currently importing the plugin using the following pattern:

  ```ts
  import { examplePlugin } from '@backstage/plugin-example-backend';

  backend.add(examplePlugin);
  ```

  It should be migrated to this:

  ```ts
  backend.add(import('@backstage/plugin-example-backend'));
  ```

- Updated dependencies
  - @backstage/backend-tasks@0.5.8
  - @backstage/backend-common@0.19.5
  - @backstage/config@1.1.0
  - @backstage/plugin-explore-common@0.0.2
  - @backstage/plugin-search-common@1.2.6
  - @backstage/backend-plugin-api@0.6.3
  - @backstage/plugin-search-backend-node@1.2.7

## 0.1.7-next.3

### Patch Changes

- 71114ac50e02: The export for the new backend system has been moved to be the `default` export.

  For example, if you are currently importing the plugin using the following pattern:

  ```ts
  import { examplePlugin } from '@backstage/plugin-example-backend';

  backend.add(examplePlugin);
  ```

  It should be migrated to this:

  ```ts
  backend.add(import('@backstage/plugin-example-backend'));
  ```

- Updated dependencies
  - @backstage/config@1.1.0-next.2
  - @backstage/plugin-explore-common@0.0.2-next.0
  - @backstage/plugin-search-common@1.2.6-next.2
  - @backstage/backend-plugin-api@0.6.3-next.3
  - @backstage/backend-common@0.19.5-next.3
  - @backstage/backend-tasks@0.5.8-next.3
  - @backstage/plugin-search-backend-node@1.2.7-next.3

## 0.1.7-next.2

### Patch Changes

- Updated dependencies
  - @backstage/config@1.1.0-next.1
  - @backstage/backend-tasks@0.5.8-next.2
  - @backstage/backend-common@0.19.5-next.2
  - @backstage/backend-plugin-api@0.6.3-next.2
  - @backstage/plugin-search-backend-node@1.2.7-next.2
  - @backstage/plugin-explore-common@0.0.1
  - @backstage/plugin-search-common@1.2.6-next.1

## 0.1.7-next.1

### Patch Changes

- Updated dependencies
  - @backstage/config@1.1.0-next.0
  - @backstage/backend-tasks@0.5.8-next.1
  - @backstage/backend-common@0.19.5-next.1
  - @backstage/backend-plugin-api@0.6.3-next.1
  - @backstage/plugin-search-backend-node@1.2.7-next.1
  - @backstage/plugin-explore-common@0.0.1
  - @backstage/plugin-search-common@1.2.6-next.0

## 0.1.6-next.0

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.19.4-next.0
  - @backstage/backend-tasks@0.5.7-next.0
  - @backstage/backend-plugin-api@0.6.2-next.0
  - @backstage/config@1.0.8
  - @backstage/plugin-explore-common@0.0.1
  - @backstage/plugin-search-backend-node@1.2.6-next.0
  - @backstage/plugin-search-common@1.2.5

## 0.1.4

### Patch Changes

- 629cbd194a87: Use `coreServices.rootConfig` instead of `coreService.config`
- 29f77f923c71: Ensure that all services are dependency injected into the module instead of taken from options
- 12a8c94eda8d: Add package repository and homepage metadata
- 6694e79ab396: Breaking change for the alpha export moved `schedule` from module options into app-config for the new backend system. You can now pass in a `TaskScheduleDefinitionConfig` through the `search.collators.explore.schedule` configuration key.
- Updated dependencies
  - @backstage/backend-common@0.19.2
  - @backstage/backend-plugin-api@0.6.0
  - @backstage/plugin-search-backend-node@1.2.4
  - @backstage/backend-tasks@0.5.5
  - @backstage/config@1.0.8
  - @backstage/plugin-explore-common@0.0.1
  - @backstage/plugin-search-common@1.2.5

## 0.1.4-next.2

### Patch Changes

- 29f77f923c71: Ensure that all services are dependency injected into the module instead of taken from options
- Updated dependencies
  - @backstage/backend-plugin-api@0.6.0-next.2
  - @backstage/backend-tasks@0.5.5-next.2
  - @backstage/backend-common@0.19.2-next.2
  - @backstage/plugin-search-backend-node@1.2.4-next.2

## 0.1.4-next.1

### Patch Changes

- 629cbd194a87: Use `coreServices.rootConfig` instead of `coreService.config`
- 12a8c94eda8d: Add package repository and homepage metadata
- Updated dependencies
  - @backstage/backend-common@0.19.2-next.1
  - @backstage/plugin-search-backend-node@1.2.4-next.1
  - @backstage/backend-plugin-api@0.6.0-next.1
  - @backstage/backend-tasks@0.5.5-next.1
  - @backstage/config@1.0.8
  - @backstage/plugin-explore-common@0.0.1
  - @backstage/plugin-search-common@1.2.5

## 0.1.4-next.0

### Patch Changes

- Updated dependencies
  - @backstage/plugin-search-backend-node@1.2.4-next.0
  - @backstage/backend-common@0.19.2-next.0
  - @backstage/backend-plugin-api@0.5.5-next.0
  - @backstage/backend-tasks@0.5.5-next.0
  - @backstage/config@1.0.8
  - @backstage/plugin-explore-common@0.0.1
  - @backstage/plugin-search-common@1.2.5

## 0.1.3

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.19.1
  - @backstage/backend-plugin-api@0.5.4
  - @backstage/backend-tasks@0.5.4
  - @backstage/config@1.0.8
  - @backstage/plugin-explore-common@0.0.1
  - @backstage/plugin-search-backend-node@1.2.3
  - @backstage/plugin-search-common@1.2.5

## 0.1.3-next.0

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.19.1-next.0
  - @backstage/backend-plugin-api@0.5.4-next.0
  - @backstage/backend-tasks@0.5.4-next.0
  - @backstage/config@1.0.8
  - @backstage/plugin-explore-common@0.0.1
  - @backstage/plugin-search-backend-node@1.2.3-next.0
  - @backstage/plugin-search-common@1.2.5-next.0

## 0.1.2

### Patch Changes

- a5baeea2cb87: Allows for an optional `tokenManager` to authenticate requests from the collator to the explore backend. For example:

  ```diff
    indexBuilder.addCollator({
      schedule: every10MinutesSchedule,
      factory: ToolDocumentCollatorFactory.fromConfig(env.config, {
        discovery: env.discovery,
        logger: env.logger,
      + tokenManager: env.tokenManager,
      }),
    });
  ```

- Updated dependencies
  - @backstage/backend-common@0.19.0
  - @backstage/backend-plugin-api@0.5.3
  - @backstage/backend-tasks@0.5.3
  - @backstage/plugin-search-backend-node@1.2.2
  - @backstage/config@1.0.8
  - @backstage/plugin-explore-common@0.0.1
  - @backstage/plugin-search-common@1.2.4

## 0.1.2-next.2

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.19.0-next.2
  - @backstage/backend-plugin-api@0.5.3-next.2
  - @backstage/backend-tasks@0.5.3-next.2
  - @backstage/config@1.0.7
  - @backstage/plugin-explore-common@0.0.1
  - @backstage/plugin-search-backend-node@1.2.2-next.2
  - @backstage/plugin-search-common@1.2.4-next.0

## 0.1.2-next.1

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.19.0-next.1
  - @backstage/backend-plugin-api@0.5.3-next.1
  - @backstage/backend-tasks@0.5.3-next.1
  - @backstage/plugin-search-backend-node@1.2.2-next.1
  - @backstage/config@1.0.7
  - @backstage/plugin-explore-common@0.0.1
  - @backstage/plugin-search-common@1.2.4-next.0

## 0.1.2-next.0

### Patch Changes

- a5baeea2cb87: Allows for an optional `tokenManager` to authenticate requests from the collator to the explore backend. For example:

  ```diff
    indexBuilder.addCollator({
      schedule: every10MinutesSchedule,
      factory: ToolDocumentCollatorFactory.fromConfig(env.config, {
        discovery: env.discovery,
        logger: env.logger,
      + tokenManager: env.tokenManager,
      }),
    });
  ```

- Updated dependencies
  - @backstage/backend-common@0.18.6-next.0
  - @backstage/config@1.0.7
  - @backstage/backend-plugin-api@0.5.3-next.0
  - @backstage/backend-tasks@0.5.3-next.0
  - @backstage/plugin-explore-common@0.0.1
  - @backstage/plugin-search-backend-node@1.2.2-next.0
  - @backstage/plugin-search-common@1.2.3

## 0.1.1

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.18.5
  - @backstage/backend-tasks@0.5.2
  - @backstage/plugin-search-backend-node@1.2.1
  - @backstage/backend-plugin-api@0.5.2
  - @backstage/config@1.0.7
  - @backstage/plugin-explore-common@0.0.1
  - @backstage/plugin-search-common@1.2.3

## 0.1.1-next.1

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.18.5-next.1
  - @backstage/backend-tasks@0.5.2-next.1
  - @backstage/plugin-search-backend-node@1.2.1-next.1
  - @backstage/backend-plugin-api@0.5.2-next.1
  - @backstage/config@1.0.7

## 0.1.1-next.0

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.18.5-next.0
  - @backstage/backend-tasks@0.5.2-next.0
  - @backstage/plugin-search-backend-node@1.2.1-next.0
  - @backstage/backend-plugin-api@0.5.2-next.0
  - @backstage/config@1.0.7
  - @backstage/plugin-explore-common@0.0.1
  - @backstage/plugin-search-common@1.2.3

## 0.1.0

### Minor Changes

- 01ae205352e: Package introduced to export search backend modules that can be used with the new backend system to extend search with plugin specific functionality, such as collators. For documentation on how to migrate, check out the [how to migrate to the new backend system guide](https://backstage.io/docs/features/search/how-to-guides/#how-to-migrate-your-backend-installation-to-use-search-together-with-the-new-backend-system).

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.18.4
  - @backstage/backend-tasks@0.5.1
  - @backstage/plugin-search-backend-node@1.2.0
  - @backstage/backend-plugin-api@0.5.1
  - @backstage/config@1.0.7
  - @backstage/plugin-explore-common@0.0.1
  - @backstage/plugin-search-common@1.2.3

## 0.1.0-next.1

### Patch Changes

- Updated dependencies
  - @backstage/backend-common@0.18.4-next.2
  - @backstage/backend-plugin-api@0.5.1-next.2
  - @backstage/backend-tasks@0.5.1-next.2
  - @backstage/config@1.0.7
  - @backstage/plugin-explore-common@0.0.1
  - @backstage/plugin-search-backend-node@1.2.0-next.2
  - @backstage/plugin-search-common@1.2.3-next.0

## 0.1.0-next.0

### Minor Changes

- 01ae205352e: Package introduced to export search backend modules that can be used with the new backend system to extend search with plugin specific functionality, such as collators. For documentation on how to migrate, check out the [how to migrate to the new backend system guide](https://backstage.io/docs/features/search/how-to-guides/#how-to-migrate-your-backend-installation-to-use-search-together-with-the-new-backend-system).

### Patch Changes

- Updated dependencies
  - @backstage/backend-tasks@0.5.1-next.1
  - @backstage/plugin-search-backend-node@1.2.0-next.1
  - @backstage/backend-common@0.18.4-next.1
  - @backstage/backend-plugin-api@0.5.1-next.1
  - @backstage/config@1.0.7
  - @backstage/plugin-explore-common@0.0.1
  - @backstage/plugin-search-common@1.2.3-next.0

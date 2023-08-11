/*
 * Copyright 2022 The Backstage Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {
  coreServices,
  createBackendModule,
} from '@backstage/backend-plugin-api';
import { loggerToWinstonLogger } from '@backstage/backend-common';
import { catalogProcessingExtensionPoint } from '@backstage/plugin-catalog-node/alpha';
import {
  GroupTransformer,
  OrganizationTransformer,
  UserTransformer,
} from '@backstage/plugin-catalog-backend-module-msgraph';
import { MicrosoftGraphOrgEntityProvider } from '../processors';

/**
 * Options for {@link catalogModuleMicrosoftGraphOrgEntityProvider}.
 *
 * @alpha
 */
export interface CatalogModuleMicrosoftGraphOrgEntityProviderOptions {
  /**
   * The function that transforms a user entry in msgraph to an entity.
   * Optionally, you can pass separate transformers per provider ID.
   */
  userTransformer?: UserTransformer | Record<string, UserTransformer>;

  /**
   * The function that transforms a group entry in msgraph to an entity.
   * Optionally, you can pass separate transformers per provider ID.
   */
  groupTransformer?: GroupTransformer | Record<string, GroupTransformer>;

  /**
   * The function that transforms an organization entry in msgraph to an entity.
   * Optionally, you can pass separate transformers per provider ID.
   */
  organizationTransformer?:
    | OrganizationTransformer
    | Record<string, OrganizationTransformer>;
}

/**
 * Registers the MicrosoftGraphOrgEntityProvider with the catalog processing extension point.
 *
 * @alpha
 */
export const catalogModuleMicrosoftGraphOrgEntityProvider = createBackendModule(
  {
    pluginId: 'catalog',
    moduleId: 'microsoftGraphOrgEntityProvider',
    register(
      env,
      options?: CatalogModuleMicrosoftGraphOrgEntityProviderOptions,
    ) {
      env.registerInit({
        deps: {
          catalog: catalogProcessingExtensionPoint,
          config: coreServices.rootConfig,
          logger: coreServices.logger,
          scheduler: coreServices.scheduler,
        },
        async init({ catalog, config, logger, scheduler }) {
          catalog.addEntityProvider(
            MicrosoftGraphOrgEntityProvider.fromConfig(config, {
              groupTransformer: options?.groupTransformer,
              logger: loggerToWinstonLogger(logger),
              organizationTransformer: options?.organizationTransformer,
              scheduler,
              userTransformer: options?.userTransformer,
            }),
          );
        },
      });
    },
  },
);

/*
 * Copyright 2021 The Backstage Authors
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

import { loggerToWinstonLogger } from '@backstage/backend-common';
import {
  coreServices,
  createBackendPlugin,
} from '@backstage/backend-plugin-api';
import { PermissionPolicy } from '@backstage/plugin-permission-node';
import {
  policyExtensionPoint,
  PolicyExtensionPoint,
} from '@backstage/plugin-permission-node/alpha';
import { createRouter } from './service';

class PolicyExtensionPointImpl implements PolicyExtensionPoint {
  public policy: PermissionPolicy | undefined;

  setPolicy(policy: PermissionPolicy): void {
    if (this.policy) {
      throw new Error('Policy already set');
    }
    this.policy = policy;
  }
}

/**
 * Permission plugin
 *
 * @alpha
 */
export const permissionPlugin = createBackendPlugin({
  pluginId: 'permission',
  register(env) {
    const policies = new PolicyExtensionPointImpl();

    env.registerExtensionPoint(policyExtensionPoint, policies);

    env.registerInit({
      deps: {
        http: coreServices.httpRouter,
        config: coreServices.rootConfig,
        logger: coreServices.logger,
        discovery: coreServices.discovery,
        identity: coreServices.identity,
      },
      async init({ http, config, logger, discovery, identity }) {
        const winstonLogger = loggerToWinstonLogger(logger);
        if (!policies.policy) {
          throw new Error(
            'No policy module installed! Please install a policy module. If you want to allow all requests, use @backstage/plugin-permission-backend-module-allow-all-policy permissionModuleAllowAllPolicy',
          );
        }

        http.use(
          await createRouter({
            config,
            discovery,
            identity,
            logger: winstonLogger,
            policy: policies.policy,
          }),
        );
      },
    });
  },
});

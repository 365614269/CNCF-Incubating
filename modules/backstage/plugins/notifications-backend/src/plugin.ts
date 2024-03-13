/*
 * Copyright 2023 The Backstage Authors
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
  createBackendPlugin,
} from '@backstage/backend-plugin-api';
import { createRouter } from './service/router';
import { signalsServiceRef } from '@backstage/plugin-signals-node';
import {
  NotificationProcessor,
  notificationsProcessingExtensionPoint,
  NotificationsProcessingExtensionPoint,
} from '@backstage/plugin-notifications-node';

class NotificationsProcessingExtensionPointImpl
  implements NotificationsProcessingExtensionPoint
{
  #processors = new Array<NotificationProcessor>();

  addProcessor(
    ...processors: Array<NotificationProcessor | Array<NotificationProcessor>>
  ): void {
    this.#processors.push(...processors.flat());
  }

  get processors() {
    return this.#processors;
  }
}

/**
 * Notifications backend plugin
 *
 * @public
 */
export const notificationsPlugin = createBackendPlugin({
  pluginId: 'notifications',
  register(env) {
    const processingExtensions =
      new NotificationsProcessingExtensionPointImpl();
    env.registerExtensionPoint(
      notificationsProcessingExtensionPoint,
      processingExtensions,
    );

    env.registerInit({
      deps: {
        auth: coreServices.auth,
        httpAuth: coreServices.httpAuth,
        userInfo: coreServices.userInfo,
        httpRouter: coreServices.httpRouter,
        logger: coreServices.logger,
        database: coreServices.database,
        discovery: coreServices.discovery,
        signals: signalsServiceRef,
      },
      async init({
        auth,
        httpAuth,
        userInfo,
        httpRouter,
        logger,
        database,
        discovery,
        signals,
      }) {
        httpRouter.use(
          await createRouter({
            auth,
            httpAuth,
            userInfo,
            logger,
            database,
            discovery,
            signals,
            processors: processingExtensions.processors,
          }),
        );
      },
    });
  },
});

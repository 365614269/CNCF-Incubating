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

import {
  DatabaseManager,
  getRootLogger,
  PluginDatabaseManager,
} from '@backstage/backend-common';
import { Config } from '@backstage/config';
import { once } from 'lodash';
import { Duration } from 'luxon';
import { Logger } from 'winston';
import { migrateBackendTasks } from '../database/migrateBackendTasks';
import { PluginTaskSchedulerImpl } from './PluginTaskSchedulerImpl';
import { PluginTaskSchedulerJanitor } from './PluginTaskSchedulerJanitor';
import { PluginTaskScheduler } from './types';

/**
 * Deals with the scheduling of distributed tasks.
 *
 * @public
 */
export class TaskScheduler {
  static fromConfig(
    config: Config,
    options?: {
      databaseManager?: DatabaseManager;
      logger?: Logger;
    },
  ): TaskScheduler {
    const databaseManager =
      options?.databaseManager ?? DatabaseManager.fromConfig(config);
    const logger = (options?.logger || getRootLogger()).child({
      type: 'taskManager',
    });
    return new TaskScheduler(databaseManager, logger);
  }

  constructor(
    private readonly databaseManager: DatabaseManager,
    private readonly logger: Logger,
  ) {}

  /**
   * Instantiates a task manager instance for the given plugin.
   *
   * @param pluginId - The unique ID of the plugin, for example "catalog"
   * @returns A {@link PluginTaskScheduler} instance
   */
  forPlugin(pluginId: string): PluginTaskScheduler {
    return TaskScheduler.forPlugin({
      pluginId,
      databaseManager: this.databaseManager.forPlugin(pluginId),
      logger: this.logger,
    });
  }

  static forPlugin(opts: {
    pluginId: string;
    databaseManager: PluginDatabaseManager;
    logger: Logger;
  }): PluginTaskScheduler {
    const databaseFactory = once(async () => {
      const knex = await opts.databaseManager.getClient();

      if (!opts.databaseManager.migrations?.skip) {
        await migrateBackendTasks(knex);
      }

      const janitor = new PluginTaskSchedulerJanitor({
        knex,
        waitBetweenRuns: Duration.fromObject({ minutes: 1 }),
        logger: opts.logger,
      });
      janitor.start();

      return knex;
    });

    return new PluginTaskSchedulerImpl(databaseFactory, opts.logger);
  }
}

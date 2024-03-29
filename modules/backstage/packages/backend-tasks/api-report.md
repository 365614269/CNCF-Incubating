## API Report File for "@backstage/backend-tasks"

> Do not edit this file. It is a report generated by [API Extractor](https://api-extractor.com/).

```ts
import { Config } from '@backstage/config';
import { Duration } from 'luxon';
import { HumanDuration as HumanDuration_2 } from '@backstage/types';
import { JsonObject } from '@backstage/types';
import { LegacyRootDatabaseService } from '@backstage/backend-common';
import { Logger } from 'winston';
import { PluginDatabaseManager } from '@backstage/backend-common';

// @public @deprecated
export type HumanDuration = HumanDuration_2;

// @public
export interface PluginTaskScheduler {
  createScheduledTaskRunner(schedule: TaskScheduleDefinition): TaskRunner;
  getScheduledTasks(): Promise<TaskDescriptor[]>;
  scheduleTask(
    task: TaskScheduleDefinition & TaskInvocationDefinition,
  ): Promise<void>;
  triggerTask(id: string): Promise<void>;
}

// @public
export function readTaskScheduleDefinitionFromConfig(
  config: Config,
): TaskScheduleDefinition;

// @public
export type TaskDescriptor = {
  id: string;
  scope: 'global' | 'local';
  settings: {
    version: number;
  } & JsonObject;
};

// @public
export type TaskFunction =
  | ((abortSignal: AbortSignal) => void | Promise<void>)
  | (() => void | Promise<void>);

// @public
export interface TaskInvocationDefinition {
  fn: TaskFunction;
  id: string;
  signal?: AbortSignal;
}

// @public
export interface TaskRunner {
  run(task: TaskInvocationDefinition): Promise<void>;
}

// @public
export interface TaskScheduleDefinition {
  frequency:
    | {
        cron: string;
      }
    | Duration
    | HumanDuration_2;
  initialDelay?: Duration | HumanDuration_2;
  scope?: 'global' | 'local';
  timeout: Duration | HumanDuration_2;
}

// @public
export interface TaskScheduleDefinitionConfig {
  frequency:
    | {
        cron: string;
      }
    | string
    | HumanDuration_2;
  initialDelay?: string | HumanDuration_2;
  scope?: 'global' | 'local';
  timeout: string | HumanDuration_2;
}

// @public
export class TaskScheduler {
  constructor(databaseManager: LegacyRootDatabaseService, logger: Logger);
  forPlugin(pluginId: string): PluginTaskScheduler;
  // (undocumented)
  static forPlugin(opts: {
    pluginId: string;
    databaseManager: PluginDatabaseManager;
    logger: Logger;
  }): PluginTaskScheduler;
  // (undocumented)
  static fromConfig(
    config: Config,
    options?: {
      databaseManager?: LegacyRootDatabaseService;
      logger?: Logger;
    },
  ): TaskScheduler;
}
```

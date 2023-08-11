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

import { JsonValue, JsonObject, Observable } from '@backstage/types';
import { TaskSpec, TaskStep } from '@backstage/plugin-scaffolder-common';
import { TaskSecrets } from '@backstage/plugin-scaffolder-node';
import { TemplateAction } from '@backstage/plugin-scaffolder-node';

/**
 * The status of each step of the Task
 *
 * @public
 */
export type TaskStatus =
  | 'cancelled'
  | 'completed'
  | 'failed'
  | 'open'
  | 'processing';

/**
 * The state of a completed task.
 *
 * @public
 */
export type TaskCompletionState = 'failed' | 'completed';

/**
 * SerializedTask
 *
 * @public
 */
export type SerializedTask = {
  id: string;
  spec: TaskSpec;
  status: TaskStatus;
  createdAt: string;
  lastHeartbeatAt?: string;
  createdBy?: string;
  secrets?: TaskSecrets;
};

/**
 * TaskEventType
 *
 * @public
 */
export type TaskEventType = 'completion' | 'log' | 'cancelled';

/**
 * SerializedTaskEvent
 *
 * @public
 */
export type SerializedTaskEvent = {
  id: number;
  taskId: string;
  body: JsonObject;
  type: TaskEventType;
  createdAt: string;
};

/**
 * The result of {@link TaskBroker.dispatch}
 *
 * @public
 */
export type TaskBrokerDispatchResult = {
  taskId: string;
};

/**
 * The options passed to {@link TaskBroker.dispatch}
 * Currently a spec and optional secrets
 *
 * @public
 */
export type TaskBrokerDispatchOptions = {
  spec: TaskSpec;
  secrets?: TaskSecrets;
  createdBy?: string;
};

/**
 * Task
 *
 * @public
 */
export interface TaskContext {
  cancelSignal: AbortSignal;
  spec: TaskSpec;
  secrets?: TaskSecrets;
  createdBy?: string;
  done: boolean;
  isDryRun?: boolean;

  complete(result: TaskCompletionState, metadata?: JsonObject): Promise<void>;

  emitLog(message: string, logMetadata?: JsonObject): Promise<void>;

  getWorkspaceName(): Promise<string>;
}

/**
 * TaskBroker
 *
 * @public
 */
export interface TaskBroker {
  cancel?(taskId: string): Promise<void>;

  claim(): Promise<TaskContext>;

  dispatch(
    options: TaskBrokerDispatchOptions,
  ): Promise<TaskBrokerDispatchResult>;

  vacuumTasks(options: { timeoutS: number }): Promise<void>;

  event$(options: {
    taskId: string;
    after: number | undefined;
  }): Observable<{ events: SerializedTaskEvent[] }>;

  get(taskId: string): Promise<SerializedTask>;

  list?(options?: { createdBy?: string }): Promise<{ tasks: SerializedTask[] }>;
}

/**
 * TaskStoreEmitOptions
 *
 * @public
 */
export type TaskStoreEmitOptions<TBody = JsonObject> = {
  taskId: string;
  body: TBody;
};

/**
 * TaskStoreListEventsOptions
 *
 * @public
 */
export type TaskStoreListEventsOptions = {
  taskId: string;
  after?: number | undefined;
};

/**
 * TaskStoreShutDownTaskOptions
 *
 * @public
 */
export type TaskStoreShutDownTaskOptions = {
  taskId: string;
};

/**
 * The options passed to {@link TaskStore.createTask}
 * @public
 */
export type TaskStoreCreateTaskOptions = {
  spec: TaskSpec;
  createdBy?: string;
  secrets?: TaskSecrets;
};

/**
 * The response from {@link TaskStore.createTask}
 * @public
 */
export type TaskStoreCreateTaskResult = {
  taskId: string;
};

/**
 * TaskStore
 *
 * @public
 */
export interface TaskStore {
  cancelTask?(options: TaskStoreEmitOptions): Promise<void>;

  createTask(
    options: TaskStoreCreateTaskOptions,
  ): Promise<TaskStoreCreateTaskResult>;

  getTask(taskId: string): Promise<SerializedTask>;

  claimTask(): Promise<SerializedTask | undefined>;

  completeTask(options: {
    taskId: string;
    status: TaskStatus;
    eventBody: JsonObject;
  }): Promise<void>;

  heartbeatTask(taskId: string): Promise<void>;

  listStaleTasks(options: { timeoutS: number }): Promise<{
    tasks: { taskId: string }[];
  }>;

  list?(options: { createdBy?: string }): Promise<{ tasks: SerializedTask[] }>;

  emitLogEvent(options: TaskStoreEmitOptions): Promise<void>;

  listEvents(
    options: TaskStoreListEventsOptions,
  ): Promise<{ events: SerializedTaskEvent[] }>;

  shutdownTask?(options: TaskStoreShutDownTaskOptions): Promise<void>;
}

export type WorkflowResponse = { output: { [key: string]: JsonValue } };

export interface WorkflowRunner {
  execute(task: TaskContext): Promise<WorkflowResponse>;
}

export type TaskTrackType = {
  markCancelled: (step: TaskStep) => Promise<void>;
  markFailed: (step: TaskStep, err: Error) => Promise<void>;
  markSuccessful: () => Promise<void>;
  skipDryRun: (
    step: TaskStep,
    action: TemplateAction<JsonObject>,
  ) => Promise<void>;
};

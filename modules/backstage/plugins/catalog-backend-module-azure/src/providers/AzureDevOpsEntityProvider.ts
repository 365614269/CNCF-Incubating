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

import { PluginTaskScheduler, TaskRunner } from '@backstage/backend-tasks';
import { Config } from '@backstage/config';
import { AzureIntegration, ScmIntegrations } from '@backstage/integration';
import {
  EntityProvider,
  EntityProviderConnection,
  locationSpecToLocationEntity,
} from '@backstage/plugin-catalog-node';
import { LocationSpec } from '@backstage/plugin-catalog-common';
import { readAzureDevOpsConfigs } from './config';
import { Logger } from 'winston';
import { AzureDevOpsConfig } from './types';
import * as uuid from 'uuid';
import { codeSearch, CodeSearchResultItem } from '../lib';

/**
 * Provider which discovers catalog files within an Azure DevOps repositories.
 *
 * Use `AzureDevOpsEntityProvider.fromConfig(...)` to create instances.
 *
 * @public
 */
export class AzureDevOpsEntityProvider implements EntityProvider {
  private readonly logger: Logger;
  private readonly scheduleFn: () => Promise<void>;
  private connection?: EntityProviderConnection;

  static fromConfig(
    configRoot: Config,
    options: {
      logger: Logger;
      schedule?: TaskRunner;
      scheduler?: PluginTaskScheduler;
    },
  ): AzureDevOpsEntityProvider[] {
    const providerConfigs = readAzureDevOpsConfigs(configRoot);

    if (!options.schedule && !options.scheduler) {
      throw new Error('Either schedule or scheduler must be provided.');
    }

    return providerConfigs.map(providerConfig => {
      const integration = ScmIntegrations.fromConfig(configRoot).azure.byHost(
        providerConfig.host,
      );

      if (!integration) {
        throw new Error(
          `There is no Azure integration for host ${providerConfig.host}. Please add a configuration entry for it under integrations.azure`,
        );
      }

      if (!options.schedule && !providerConfig.schedule) {
        throw new Error(
          `No schedule provided neither via code nor config for AzureDevOpsEntityProvider:${providerConfig.id}.`,
        );
      }

      const taskRunner =
        options.schedule ??
        options.scheduler!.createScheduledTaskRunner(providerConfig.schedule!);

      return new AzureDevOpsEntityProvider(
        providerConfig,
        integration,
        options.logger,
        taskRunner,
      );
    });
  }

  private constructor(
    private readonly config: AzureDevOpsConfig,
    private readonly integration: AzureIntegration,
    logger: Logger,
    taskRunner: TaskRunner,
  ) {
    this.logger = logger.child({
      target: this.getProviderName(),
    });

    this.scheduleFn = this.createScheduleFn(taskRunner);
  }

  private createScheduleFn(taskRunner: TaskRunner): () => Promise<void> {
    return async () => {
      const taskId = `${this.getProviderName()}:refresh`;
      return taskRunner.run({
        id: taskId,
        fn: async () => {
          const logger = this.logger.child({
            class: AzureDevOpsEntityProvider.prototype.constructor.name,
            taskId,
            taskInstanceId: uuid.v4(),
          });

          try {
            await this.refresh(logger);
          } catch (error) {
            logger.error(`${this.getProviderName()} refresh failed`, error);
          }
        },
      });
    };
  }

  /** {@inheritdoc @backstage/plugin-catalog-backend#EntityProvider.getProviderName} */
  getProviderName(): string {
    return `AzureDevOpsEntityProvider:${this.config.id}`;
  }

  /** {@inheritdoc @backstage/plugin-catalog-backend#EntityProvider.connect} */
  async connect(connection: EntityProviderConnection): Promise<void> {
    this.connection = connection;
    await this.scheduleFn();
  }

  async refresh(logger: Logger) {
    if (!this.connection) {
      throw new Error('Not initialized');
    }

    logger.info('Discovering Azure DevOps catalog files');

    const files = await codeSearch(
      this.integration.config,
      this.config.organization,
      this.config.project,
      this.config.repository,
      this.config.path,
    );

    logger.info(`Discovered ${files.length} catalog files`);

    const locations = files.map(key => this.createLocationSpec(key));

    await this.connection.applyMutation({
      type: 'full',
      entities: locations.map(location => {
        return {
          locationKey: this.getProviderName(),
          entity: locationSpecToLocationEntity({ location }),
        };
      }),
    });

    logger.info(
      `Committed ${locations.length} locations for AzureDevOps catalog files`,
    );
  }

  private createLocationSpec(file: CodeSearchResultItem): LocationSpec {
    const target = this.createObjectUrl(file);

    return {
      type: 'url',
      target: target,
      presence: 'required',
    };
  }

  private createObjectUrl(file: CodeSearchResultItem): string {
    const baseUrl = `https://${this.config.host}/${this.config.organization}/${file.project.name}`;

    let fullUrl = `${baseUrl}/_git/${file.repository.name}?path=${file.path}`;
    if (this.config.branch) {
      fullUrl += `&version=GB${this.config.branch}`;
    }

    return encodeURI(fullUrl);
  }
}

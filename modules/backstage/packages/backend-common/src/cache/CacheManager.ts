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

import { Config } from '@backstage/config';
import Keyv from 'keyv';
import KeyvMemcache from '@keyv/memcache';
import KeyvRedis from '@keyv/redis';
import {
  CacheService,
  CacheServiceOptions,
  LoggerService,
} from '@backstage/backend-plugin-api';
import { getRootLogger } from '../logging';
import { DefaultCacheClient } from './CacheClient';
import { CacheManagerOptions, PluginCacheManager } from './types';

/**
 * Implements a Cache Manager which will automatically create new cache clients
 * for plugins when requested. All requested cache clients are created with the
 * connection details provided.
 *
 * @public
 */
export class CacheManager {
  /**
   * Keys represent supported `backend.cache.store` values, mapped to factories
   * that return Keyv instances appropriate to the store.
   */
  private readonly storeFactories = {
    redis: this.getRedisClient,
    memcache: this.getMemcacheClient,
    memory: this.getMemoryClient,
  };

  /**
   * Shared memory store for the in-memory cache client. Sharing the same Map
   * instance ensures get/set/delete operations hit the same store, regardless
   * of where/when a client is instantiated.
   */
  private readonly memoryStore = new Map();

  private readonly logger: LoggerService;
  private readonly store: keyof CacheManager['storeFactories'];
  private readonly connection: string;
  private readonly useRedisSets: boolean;
  private readonly errorHandler: CacheManagerOptions['onError'];

  /**
   * Creates a new {@link CacheManager} instance by reading from the `backend`
   * config section, specifically the `.cache` key.
   *
   * @param config - The loaded application configuration.
   */
  static fromConfig(
    config: Config,
    options: CacheManagerOptions = {},
  ): CacheManager {
    // If no `backend.cache` config is provided, instantiate the CacheManager
    // with an in-memory cache client.
    const store = config.getOptionalString('backend.cache.store') || 'memory';
    const connectionString =
      config.getOptionalString('backend.cache.connection') || '';
    const useRedisSets =
      config.getOptionalBoolean('backend.cache.useRedisSets') ?? true;
    const logger = (options.logger || getRootLogger()).child({
      type: 'cacheManager',
    });
    return new CacheManager(
      store,
      connectionString,
      useRedisSets,
      logger,
      options.onError,
    );
  }

  private constructor(
    store: string,
    connectionString: string,
    useRedisSets: boolean,
    logger: LoggerService,
    errorHandler: CacheManagerOptions['onError'],
  ) {
    if (!this.storeFactories.hasOwnProperty(store)) {
      throw new Error(`Unknown cache store: ${store}`);
    }
    this.logger = logger;
    this.store = store as keyof CacheManager['storeFactories'];
    this.connection = connectionString;
    this.useRedisSets = useRedisSets;
    this.errorHandler = errorHandler;
  }

  /**
   * Generates a PluginCacheManager for consumption by plugins.
   *
   * @param pluginId - The plugin that the cache manager should be created for.
   *        Plugin names should be unique.
   */
  forPlugin(pluginId: string): PluginCacheManager {
    return {
      getClient: (defaultOptions = {}) => {
        const clientFactory = (options: CacheServiceOptions) => {
          const concreteClient = this.getClientWithTtl(
            pluginId,
            options.defaultTtl,
          );

          // Always provide an error handler to avoid stopping the process.
          concreteClient.on('error', (err: Error) => {
            // In all cases, just log the error.
            this.logger.error('Failed to create cache client', err);

            // Invoke any custom error handler if provided.
            if (typeof this.errorHandler === 'function') {
              this.errorHandler(err);
            }
          });

          return concreteClient;
        };

        return new DefaultCacheClient(
          clientFactory(defaultOptions),
          clientFactory,
          defaultOptions,
        );
      },
    };
  }

  private getClientWithTtl(pluginId: string, ttl: number | undefined): Keyv {
    return this.storeFactories[this.store].call(this, pluginId, ttl);
  }

  private getRedisClient(
    pluginId: string,
    defaultTtl: number | undefined,
  ): Keyv {
    return new Keyv({
      namespace: pluginId,
      ttl: defaultTtl,
      store: new KeyvRedis(this.connection),
      useRedisSets: this.useRedisSets,
    });
  }

  private getMemcacheClient(
    pluginId: string,
    defaultTtl: number | undefined,
  ): Keyv {
    return new Keyv({
      namespace: pluginId,
      ttl: defaultTtl,
      store: new KeyvMemcache(this.connection),
    });
  }

  private getMemoryClient(
    pluginId: string,
    defaultTtl: number | undefined,
  ): Keyv {
    return new Keyv({
      namespace: pluginId,
      ttl: defaultTtl,
      store: this.memoryStore,
    });
  }
}

/** @public */
export function cacheToPluginCacheManager(
  cache: CacheService,
): PluginCacheManager {
  return {
    getClient: (opts: CacheServiceOptions) => cache.withOptions(opts),
  };
}

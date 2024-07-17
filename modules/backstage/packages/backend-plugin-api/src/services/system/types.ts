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

import { BackendFeature } from '../../types';

/**
 * TODO
 *
 * @public
 */
export type ServiceRef<
  TService,
  TScope extends 'root' | 'plugin' = 'root' | 'plugin',
> = {
  id: string;

  /**
   * This determines the scope at which this service is available.
   *
   * Root scoped services are available to all other services but
   * may only depend on other root scoped services.
   *
   * Plugin scoped services are only available to other plugin scoped
   * services but may depend on all other services.
   */
  scope: TScope;

  /**
   * Utility for getting the type of the service, using `typeof serviceRef.T`.
   * Attempting to actually read this value will result in an exception.
   */
  T: TService;

  $$type: '@backstage/ServiceRef';
};

/** @public */
export interface ServiceFactory<
  TService = unknown,
  TScope extends 'plugin' | 'root' = 'plugin' | 'root',
> extends BackendFeature {
  service: ServiceRef<TService, TScope>;
}

/**
 * @public
 * @deprecated This type exists only as a helper for old code that relied on `createServiceFactory` to return `() => ServiceFactory` instead of `ServiceFactory`. You should remove the `()` parentheses at the end of your usages. This type will be removed in a future release.
 */
export interface ServiceFactoryCompat<
  TService = unknown,
  TScope extends 'plugin' | 'root' = 'plugin' | 'root',
  TOpts extends object | undefined = undefined,
> extends ServiceFactory<TService, TScope> {
  /**
   * @deprecated Callable service factories will be removed in a future release, please re-implement the service factory using the available APIs instead. If no options are being passed, you can simply remove the trailing `()`.
   */
  (
    ...options: undefined extends TOpts ? [] : [options?: TOpts]
  ): ServiceFactory<TService, TScope>;
}

/** @internal */
export interface InternalServiceFactory<
  TService = unknown,
  TScope extends 'plugin' | 'root' = 'plugin' | 'root',
> extends ServiceFactory<TService, TScope> {
  version: 'v1';
  initialization?: 'always' | 'lazy';
  deps: { [key in string]: ServiceRef<unknown> };
  createRootContext?(deps: { [key in string]: unknown }): Promise<unknown>;
  factory(
    deps: { [key in string]: unknown },
    context: unknown,
  ): Promise<TService>;
}

/**
 * Represents either a {@link ServiceFactory} or a function that returns one.
 *
 * @deprecated The support for service factory functions is deprecated and will be removed.
 * @public
 */
export type ServiceFactoryOrFunction = ServiceFactory | (() => ServiceFactory);

/** @public */
export interface ServiceRefOptions<TService, TScope extends 'root' | 'plugin'> {
  id: string;
  scope?: TScope;
  defaultFactory?(
    service: ServiceRef<TService, TScope>,
  ): Promise<ServiceFactory>;
  /**
   * @deprecated The defaultFactory must return a plain `ServiceFactory` object, support for returning a function will be removed.
   */
  defaultFactory?(
    service: ServiceRef<TService, TScope>,
  ): Promise<() => ServiceFactory>;
}

/**
 * Creates a new service definition. This overload is used to create plugin scoped services.
 *
 * @public
 */
export function createServiceRef<TService>(
  options: ServiceRefOptions<TService, 'plugin'>,
): ServiceRef<TService, 'plugin'>;

/**
 * Creates a new service definition. This overload is used to create root scoped services.
 *
 * @public
 */
export function createServiceRef<TService>(
  options: ServiceRefOptions<TService, 'root'>,
): ServiceRef<TService, 'root'>;

export function createServiceRef<TService>(
  options: ServiceRefOptions<TService, any>,
): ServiceRef<TService, any> {
  const { id, scope = 'plugin', defaultFactory } = options;
  return {
    id,
    scope,
    get T(): TService {
      throw new Error(`tried to read ServiceRef.T of ${this}`);
    },
    toString() {
      return `serviceRef{${options.id}}`;
    },
    $$type: '@backstage/ServiceRef',
    __defaultFactory: defaultFactory,
  } as ServiceRef<TService, typeof scope> & {
    __defaultFactory?: (
      service: ServiceRef<TService>,
    ) => Promise<ServiceFactory<TService> | (() => ServiceFactory<TService>)>;
  };
}

/** @ignore */
type ServiceRefsToInstances<
  T extends { [key in string]: ServiceRef<unknown> },
  TScope extends 'root' | 'plugin' = 'root' | 'plugin',
> = {
  [key in keyof T as T[key]['scope'] extends TScope ? key : never]: T[key]['T'];
};

/** @public */
export interface RootServiceFactoryOptions<
  TService,
  TImpl extends TService,
  TDeps extends { [name in string]: ServiceRef<unknown> },
> {
  /**
   * The initialization strategy for the service factory. This service is root scoped and will use `always` by default.
   *
   * @remarks
   *
   * - `always` - The service will always be initialized regardless if it is used or not.
   * - `lazy` - The service will only be initialized if it is depended on by a different service or feature.
   *
   * Service factories for root scoped services use `always` as the default, while plugin scoped services use `lazy`.
   */
  initialization?: 'always' | 'lazy';
  service: ServiceRef<TService, 'root'>;
  deps: TDeps;
  factory(deps: ServiceRefsToInstances<TDeps, 'root'>): TImpl | Promise<TImpl>;
}

/** @public */
export interface PluginServiceFactoryOptions<
  TService,
  TContext,
  TImpl extends TService,
  TDeps extends { [name in string]: ServiceRef<unknown> },
> {
  /**
   * The initialization strategy for the service factory. This service is plugin scoped and will use `lazy` by default.
   *
   * @remarks
   *
   * - `always` - The service will always be initialized regardless if it is used or not.
   * - `lazy` - The service will only be initialized if it is depended on by a different service or feature.
   *
   * Service factories for root scoped services use `always` as the default, while plugin scoped services use `lazy`.
   */
  initialization?: 'always' | 'lazy';
  service: ServiceRef<TService, 'plugin'>;
  deps: TDeps;
  createRootContext?(
    deps: ServiceRefsToInstances<TDeps, 'root'>,
  ): TContext | Promise<TContext>;
  factory(
    deps: ServiceRefsToInstances<TDeps>,
    context: TContext,
  ): TImpl | Promise<TImpl>;
}

/**
 * Creates a root scoped service factory without options.
 *
 * @public
 * @param options - The service factory configuration.
 */
export function createServiceFactory<
  TService,
  TImpl extends TService,
  TDeps extends { [name in string]: ServiceRef<unknown, 'root'> },
  TOpts extends object | undefined = undefined,
>(
  options: RootServiceFactoryOptions<TService, TImpl, TDeps>,
): ServiceFactoryCompat<TService, 'root'>;
/**
 * Creates a root scoped service factory with optional options.
 *
 * @deprecated The ability to define options for service factories is deprecated
 * and will be removed. Please use the non-callback form of createServiceFactory
 * and provide an API that allows for a simple re-implementation of the service
 * factory instead.
 * @public
 * @param options - The service factory configuration.
 */
export function createServiceFactory<
  TService,
  TImpl extends TService,
  TDeps extends { [name in string]: ServiceRef<unknown, 'root'> },
  TOpts extends object | undefined = undefined,
>(
  options: (
    options?: TOpts,
  ) => RootServiceFactoryOptions<TService, TImpl, TDeps>,
): ServiceFactoryCompat<TService, 'root', TOpts>;
/**
 * Creates a plugin scoped service factory without options.
 *
 * @public
 * @param options - The service factory configuration.
 */
export function createServiceFactory<
  TService,
  TImpl extends TService,
  TDeps extends { [name in string]: ServiceRef<unknown> },
  TContext = undefined,
  TOpts extends object | undefined = undefined,
>(
  options: PluginServiceFactoryOptions<TService, TContext, TImpl, TDeps>,
): ServiceFactoryCompat<TService, 'plugin'>;
/**
 * Creates a plugin scoped service factory with optional options.
 *
 * @deprecated The ability to define options for service factories is deprecated
 * and will be removed. Please use the non-callback form of createServiceFactory
 * and provide an API that allows for a simple re-implementation of the service
 * factory instead.
 * @public
 * @param options - The service factory configuration.
 */
export function createServiceFactory<
  TService,
  TImpl extends TService,
  TDeps extends { [name in string]: ServiceRef<unknown> },
  TContext = undefined,
  TOpts extends object | undefined = undefined,
>(
  options: (
    options?: TOpts,
  ) => PluginServiceFactoryOptions<TService, TContext, TImpl, TDeps>,
): ServiceFactoryCompat<TService, 'plugin', TOpts>;
export function createServiceFactory<
  TService,
  TImpl extends TService,
  TDeps extends { [name in string]: ServiceRef<unknown> },
  TContext,
  TOpts extends object | undefined = undefined,
>(
  options:
    | RootServiceFactoryOptions<TService, TImpl, TDeps>
    | PluginServiceFactoryOptions<TService, TContext, TImpl, TDeps>
    | ((options: TOpts) => RootServiceFactoryOptions<TService, TImpl, TDeps>)
    | ((
        options: TOpts,
      ) => PluginServiceFactoryOptions<TService, TContext, TImpl, TDeps>)
    | (() => RootServiceFactoryOptions<TService, TImpl, TDeps>)
    | (() => PluginServiceFactoryOptions<TService, TContext, TImpl, TDeps>),
): ServiceFactoryCompat<TService, 'root' | 'plugin', TOpts> {
  const configCallback =
    typeof options === 'function' ? options : () => options;
  const factory = (
    o?: TOpts,
  ): InternalServiceFactory<TService, 'plugin' | 'root'> => {
    const anyConf = configCallback(o!);
    if (anyConf.service.scope === 'root') {
      const c = anyConf as RootServiceFactoryOptions<TService, TImpl, TDeps>;
      return {
        $$type: '@backstage/BackendFeature',
        version: 'v1',
        service: c.service,
        initialization: c.initialization,
        deps: c.deps,
        factory: async (deps: TDeps) => c.factory(deps),
      };
    }
    const c = anyConf as PluginServiceFactoryOptions<
      TService,
      TContext,
      TImpl,
      TDeps
    >;
    return {
      $$type: '@backstage/BackendFeature',
      version: 'v1',
      service: c.service,
      initialization: c.initialization,
      ...('createRootContext' in c
        ? {
            createRootContext: async (deps: TDeps) =>
              c?.createRootContext?.(deps),
          }
        : {}),
      deps: c.deps,
      factory: async (deps: TDeps, ctx: TContext) => c.factory(deps, ctx),
    };
  };

  // This constructs the `ServiceFactoryCompat` type, which is both a plain
  // factory object as well as a function that can be called to construct a
  // factory, potentially with options. In the future only the plain factory
  // form will be supported, but for now we need to allow callers to call the
  // factory too.
  return Object.assign(factory, factory(undefined as TOpts));
}

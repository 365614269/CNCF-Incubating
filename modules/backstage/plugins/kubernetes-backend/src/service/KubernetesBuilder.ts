/*
 * Copyright 2020 The Backstage Authors
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
import { CatalogApi } from '@backstage/catalog-client';
import { Config } from '@backstage/config';
import { kubernetesPermissions } from '@backstage/plugin-kubernetes-common';
import { PermissionEvaluator } from '@backstage/plugin-permission-common';
import { createPermissionIntegrationRouter } from '@backstage/plugin-permission-node';
import express from 'express';
import Router from 'express-promise-router';
import { Duration } from 'luxon';
import { Logger } from 'winston';

import { getCombinedClusterSupplier } from '../cluster-locator';
import {
  KubernetesAuthTranslator,
  DispatchingKubernetesAuthTranslator,
  GoogleKubernetesAuthTranslator,
  NoopKubernetesAuthTranslator,
  AwsIamKubernetesAuthTranslator,
  GoogleServiceAccountAuthTranslator,
  AzureIdentityKubernetesAuthTranslator,
  OidcKubernetesAuthTranslator,
  AksKubernetesAuthTranslator,
} from '../kubernetes-auth-translator';

import { addResourceRoutesToRouter } from '../routes/resourcesRoutes';
import { MultiTenantServiceLocator } from '../service-locator/MultiTenantServiceLocator';
import {
  CustomResource,
  KubernetesClustersSupplier,
  KubernetesFetcher,
  KubernetesObjectsProvider,
  KubernetesObjectsProviderOptions,
  KubernetesObjectTypes,
  KubernetesServiceLocator,
  ObjectsByEntityRequest,
  ServiceLocatorMethod,
} from '../types/types';
import {
  DEFAULT_OBJECTS,
  KubernetesFanOutHandler,
} from './KubernetesFanOutHandler';
import { KubernetesClientBasedFetcher } from './KubernetesFetcher';
import { KubernetesProxy } from './KubernetesProxy';

/**
 *
 * @public
 */
export interface KubernetesEnvironment {
  logger: Logger;
  config: Config;
  catalogApi: CatalogApi;
  permissions: PermissionEvaluator;
}

/**
 * The return type of the `KubernetesBuilder.build` method
 *
 * @public
 */
export type KubernetesBuilderReturn = Promise<{
  router: express.Router;
  clusterSupplier: KubernetesClustersSupplier;
  customResources: CustomResource[];
  fetcher: KubernetesFetcher;
  proxy: KubernetesProxy;
  objectsProvider: KubernetesObjectsProvider;
  serviceLocator: KubernetesServiceLocator;
  authTranslatorMap: { [key: string]: KubernetesAuthTranslator };
}>;

/**
 *
 * @public
 */
export class KubernetesBuilder {
  private clusterSupplier?: KubernetesClustersSupplier;
  private defaultClusterRefreshInterval: Duration = Duration.fromObject({
    minutes: 60,
  });
  private objectsProvider?: KubernetesObjectsProvider;
  private fetcher?: KubernetesFetcher;
  private serviceLocator?: KubernetesServiceLocator;
  private proxy?: KubernetesProxy;
  private authTranslatorMap?: { [key: string]: KubernetesAuthTranslator };

  static createBuilder(env: KubernetesEnvironment) {
    return new KubernetesBuilder(env);
  }

  constructor(protected readonly env: KubernetesEnvironment) {}

  public async build(): KubernetesBuilderReturn {
    const logger = this.env.logger;
    const config = this.env.config;
    const permissions = this.env.permissions;

    logger.info('Initializing Kubernetes backend');

    if (!config.has('kubernetes')) {
      if (process.env.NODE_ENV !== 'development') {
        throw new Error('Kubernetes configuration is missing');
      }
      logger.warn(
        'Failed to initialize kubernetes backend: kubernetes config is missing',
      );
      return {
        router: Router(),
      } as unknown as KubernetesBuilderReturn;
    }
    const customResources = this.buildCustomResources();

    const fetcher = this.getFetcher();

    const clusterSupplier = this.getClusterSupplier();

    const authTranslatorMap = this.getAuthTranslatorMap();

    const proxy = this.getProxy(logger, clusterSupplier);

    const serviceLocator = this.getServiceLocator();

    const objectsProvider = this.getObjectsProvider({
      logger,
      fetcher,
      config,
      serviceLocator,
      customResources,
      objectTypesToFetch: this.getObjectTypesToFetch(),
    });

    const router = this.buildRouter(
      objectsProvider,
      clusterSupplier,
      this.env.catalogApi,
      proxy,
      permissions,
    );

    return {
      clusterSupplier,
      customResources,
      fetcher,
      proxy,
      objectsProvider,
      router,
      serviceLocator,
      authTranslatorMap,
    };
  }

  public setClusterSupplier(clusterSupplier?: KubernetesClustersSupplier) {
    this.clusterSupplier = clusterSupplier;
    return this;
  }

  public setDefaultClusterRefreshInterval(refreshInterval: Duration) {
    this.defaultClusterRefreshInterval = refreshInterval;
    return this;
  }

  public setObjectsProvider(objectsProvider?: KubernetesObjectsProvider) {
    this.objectsProvider = objectsProvider;
    return this;
  }

  public setFetcher(fetcher?: KubernetesFetcher) {
    this.fetcher = fetcher;
    return this;
  }

  public setServiceLocator(serviceLocator?: KubernetesServiceLocator) {
    this.serviceLocator = serviceLocator;
    return this;
  }

  public setProxy(proxy?: KubernetesProxy) {
    this.proxy = proxy;
    return this;
  }

  public setAuthTranslatorMap(authTranslatorMap: {
    [key: string]: KubernetesAuthTranslator;
  }) {
    this.authTranslatorMap = authTranslatorMap;
  }

  protected buildCustomResources() {
    const customResources: CustomResource[] = (
      this.env.config.getOptionalConfigArray('kubernetes.customResources') ?? []
    ).map(
      c =>
        ({
          group: c.getString('group'),
          apiVersion: c.getString('apiVersion'),
          plural: c.getString('plural'),
          objectType: 'customresources',
        } as CustomResource),
    );

    this.env.logger.info(
      `action=LoadingCustomResources numOfCustomResources=${customResources.length}`,
    );
    return customResources;
  }

  protected buildClusterSupplier(
    refreshInterval: Duration,
  ): KubernetesClustersSupplier {
    const config = this.env.config;
    this.clusterSupplier = getCombinedClusterSupplier(
      config,
      this.env.catalogApi,
      refreshInterval,
    );

    return this.clusterSupplier;
  }

  protected buildObjectsProvider(
    options: KubernetesObjectsProviderOptions,
  ): KubernetesObjectsProvider {
    const authTranslatorMap = this.getAuthTranslatorMap();
    this.objectsProvider = new KubernetesFanOutHandler({
      ...options,
      authTranslator: new DispatchingKubernetesAuthTranslator({
        authTranslatorMap,
      }),
    });

    return this.objectsProvider;
  }

  protected buildFetcher(): KubernetesFetcher {
    this.fetcher = new KubernetesClientBasedFetcher({
      logger: this.env.logger,
    });

    return this.fetcher;
  }

  protected buildServiceLocator(
    method: ServiceLocatorMethod,
    clusterSupplier: KubernetesClustersSupplier,
  ): KubernetesServiceLocator {
    switch (method) {
      case 'multiTenant':
        this.serviceLocator =
          this.buildMultiTenantServiceLocator(clusterSupplier);
        break;
      case 'http':
        this.serviceLocator = this.buildHttpServiceLocator(clusterSupplier);
        break;
      default:
        throw new Error(
          `Unsupported kubernetes.clusterLocatorMethod "${method}"`,
        );
    }

    return this.serviceLocator;
  }

  protected buildMultiTenantServiceLocator(
    clusterSupplier: KubernetesClustersSupplier,
  ): KubernetesServiceLocator {
    return new MultiTenantServiceLocator(clusterSupplier);
  }

  protected buildHttpServiceLocator(
    _clusterSupplier: KubernetesClustersSupplier,
  ): KubernetesServiceLocator {
    throw new Error('not implemented');
  }

  protected buildProxy(
    logger: Logger,
    clusterSupplier: KubernetesClustersSupplier,
  ): KubernetesProxy {
    const authTranslatorMap = this.getAuthTranslatorMap();
    const authTranslator = new DispatchingKubernetesAuthTranslator({
      authTranslatorMap,
    });
    this.proxy = new KubernetesProxy({
      logger,
      clusterSupplier,
      authTranslator,
    });
    return this.proxy;
  }

  protected buildRouter(
    objectsProvider: KubernetesObjectsProvider,
    clusterSupplier: KubernetesClustersSupplier,
    catalogApi: CatalogApi,
    proxy: KubernetesProxy,
    permissionApi: PermissionEvaluator,
  ): express.Router {
    const logger = this.env.logger;
    const router = Router();
    router.use('/proxy', proxy.createRequestHandler({ permissionApi }));
    router.use(express.json());
    router.use(
      createPermissionIntegrationRouter({
        permissions: kubernetesPermissions,
      }),
    );
    // @deprecated
    router.post('/services/:serviceId', async (req, res) => {
      const serviceId = req.params.serviceId;
      const requestBody: ObjectsByEntityRequest = req.body;
      try {
        const response = await objectsProvider.getKubernetesObjectsByEntity({
          entity: requestBody.entity,
          auth: requestBody.auth || {},
        });
        res.json(response);
      } catch (e) {
        logger.error(
          `action=retrieveObjectsByServiceId service=${serviceId}, error=${e}`,
        );
        res.status(500).json({ error: e.message });
      }
    });

    router.get('/clusters', async (_, res) => {
      const clusterDetails = await this.fetchClusterDetails(clusterSupplier);
      res.json({
        items: clusterDetails.map(cd => ({
          name: cd.name,
          dashboardUrl: cd.dashboardUrl,
          authProvider: cd.authProvider,
          oidcTokenProvider: cd.oidcTokenProvider,
        })),
      });
    });

    addResourceRoutesToRouter(router, catalogApi, objectsProvider);

    return router;
  }

  protected buildAuthTranslatorMap() {
    this.authTranslatorMap = {
      google: new GoogleKubernetesAuthTranslator(),
      aks: new AksKubernetesAuthTranslator(),
      aws: new AwsIamKubernetesAuthTranslator({ config: this.env.config }),
      azure: new AzureIdentityKubernetesAuthTranslator(this.env.logger),
      serviceAccount: new NoopKubernetesAuthTranslator(),
      googleServiceAccount: new GoogleServiceAccountAuthTranslator(),
      oidc: new OidcKubernetesAuthTranslator(),
      localKubectlProxy: new NoopKubernetesAuthTranslator(),
    };
    return this.authTranslatorMap;
  }

  protected async fetchClusterDetails(
    clusterSupplier: KubernetesClustersSupplier,
  ) {
    const clusterDetails = await clusterSupplier.getClusters();

    this.env.logger.info(
      `action=loadClusterDetails numOfClustersLoaded=${clusterDetails.length}`,
    );

    return clusterDetails;
  }

  protected getServiceLocatorMethod() {
    return this.env.config.getString(
      'kubernetes.serviceLocatorMethod.type',
    ) as ServiceLocatorMethod;
  }

  protected getFetcher(): KubernetesFetcher {
    return this.fetcher ?? this.buildFetcher();
  }

  protected getClusterSupplier() {
    return (
      this.clusterSupplier ??
      this.buildClusterSupplier(this.defaultClusterRefreshInterval)
    );
  }

  protected getServiceLocator(): KubernetesServiceLocator {
    return (
      this.serviceLocator ??
      this.buildServiceLocator(
        this.getServiceLocatorMethod(),
        this.getClusterSupplier(),
      )
    );
  }

  protected getObjectsProvider(options: KubernetesObjectsProviderOptions) {
    return this.objectsProvider ?? this.buildObjectsProvider(options);
  }

  protected getObjectTypesToFetch() {
    const objectTypesToFetchStrings = this.env.config.getOptionalStringArray(
      'kubernetes.objectTypes',
    ) as KubernetesObjectTypes[];

    const apiVersionOverrides = this.env.config.getOptionalConfig(
      'kubernetes.apiVersionOverrides',
    );

    let objectTypesToFetch;

    if (objectTypesToFetchStrings) {
      objectTypesToFetch = DEFAULT_OBJECTS.filter(obj =>
        objectTypesToFetchStrings.includes(obj.objectType),
      );
    }

    if (apiVersionOverrides) {
      objectTypesToFetch = objectTypesToFetch ?? DEFAULT_OBJECTS;

      for (const obj of objectTypesToFetch) {
        if (apiVersionOverrides.has(obj.objectType)) {
          obj.apiVersion = apiVersionOverrides.getString(obj.objectType);
        }
      }
    }

    return objectTypesToFetch;
  }

  protected getProxy(
    logger: Logger,
    clusterSupplier: KubernetesClustersSupplier,
  ) {
    return this.proxy ?? this.buildProxy(logger, clusterSupplier);
  }

  protected getAuthTranslatorMap() {
    return this.authTranslatorMap ?? this.buildAuthTranslatorMap();
  }
}

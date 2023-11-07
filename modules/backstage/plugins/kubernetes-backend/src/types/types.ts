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

import { Entity } from '@backstage/catalog-model';
import { Logger } from 'winston';
import type { JsonObject } from '@backstage/types';
import type {
  CustomResourceMatcher,
  FetchResponse,
  KubernetesFetchError,
  KubernetesRequestBody,
} from '@backstage/plugin-kubernetes-common';
import { Config } from '@backstage/config';
import { KubernetesCredential } from '../auth/types';

/**
 *
 * @public
 */
export interface ObjectFetchParams {
  serviceId: string;
  clusterDetails: ClusterDetails;
  credential: KubernetesCredential;
  objectTypesToFetch: Set<ObjectToFetch>;
  labelSelector?: string;
  customResources: CustomResource[];
  namespace?: string;
}

/**
 * Fetches information from a kubernetes cluster using the cluster details object to target a specific cluster
 *
 * @public
 */
export interface KubernetesFetcher {
  fetchObjectsForService(
    params: ObjectFetchParams,
  ): Promise<FetchResponseWrapper>;
  fetchPodMetricsByNamespaces(
    clusterDetails: ClusterDetails,
    credential: KubernetesCredential,
    namespaces: Set<string>,
    labelSelector?: string,
  ): Promise<FetchResponseWrapper>;
}

/**
 *
 * @public
 */
export interface FetchResponseWrapper {
  errors: KubernetesFetchError[];
  responses: FetchResponse[];
}

/**
 *
 * @public
 */
export interface ObjectToFetch {
  objectType: KubernetesObjectTypes;
  group: string;
  apiVersion: string;
  plural: string;
}

/**
 *
 * @public
 */
export interface CustomResource extends ObjectToFetch {
  objectType: 'customresources';
}

/**
 *
 * @public
 */
export type KubernetesObjectTypes =
  | 'pods'
  | 'services'
  | 'configmaps'
  | 'deployments'
  | 'limitranges'
  | 'resourcequotas'
  | 'replicasets'
  | 'horizontalpodautoscalers'
  | 'jobs'
  | 'cronjobs'
  | 'ingresses'
  | 'customresources'
  | 'statefulsets'
  | 'daemonsets';
// If updating this list, also make sure to update
// `objectTypes` and `apiVersionOverrides` in config.d.ts!

/**
 * Used to load cluster details from different sources
 * @public
 */
export interface KubernetesClustersSupplier {
  /**
   * Returns the cached list of clusters.
   *
   * Implementations _should_ cache the clusters and refresh them periodically,
   * as getClusters is called whenever the list of clusters is needed.
   */
  getClusters(): Promise<ClusterDetails[]>;
}

/**
 * @public
 */
export interface ServiceLocatorRequestContext {
  objectTypesToFetch: Set<ObjectToFetch>;
  customResources: CustomResourceMatcher[];
}

/**
 * Used to locate which cluster(s) a service is running on
 * @public
 */
export interface KubernetesServiceLocator {
  getClustersByEntity(
    entity: Entity,
    requestContext: ServiceLocatorRequestContext,
  ): Promise<{ clusters: ClusterDetails[] }>;
}

/**
 *
 * @public
 */
export type ServiceLocatorMethod = 'multiTenant' | 'http'; // TODO implement http

/**
 * Provider-specific authentication configuration
 * @public
 */
export type AuthMetadata = Record<string, string>;

/**
 *
 * @public
 */
export interface ClusterDetails {
  /**
   * Specifies the name of the Kubernetes cluster.
   */
  name: string;
  url: string;
  authMetadata: AuthMetadata;
  skipTLSVerify?: boolean;
  /**
   * Whether to skip the lookup to the metrics server to retrieve pod resource usage.
   * It is not guaranteed that the Kubernetes distro has the metrics server installed.
   */
  skipMetricsLookup?: boolean;
  caData?: string | undefined;
  caFile?: string | undefined;
  /**
   * Specifies the link to the Kubernetes dashboard managing this cluster.
   * @remarks
   * Note that you should specify the app used for the dashboard
   * using the dashboardApp property, in order to properly format
   * links to kubernetes resources, otherwise it will assume that you're running the standard one.
   * @see dashboardApp
   * @see dashboardParameters
   */
  dashboardUrl?: string;
  /**
   * Specifies the app that provides the Kubernetes dashboard.
   * This will be used for formatting links to kubernetes objects inside the dashboard.
   * @remarks
   * The existing apps are: standard, rancher, openshift, gke, aks, eks
   * Note that it will default to the regular dashboard provided by the Kubernetes project (standard).
   * Note that you can add your own formatter by registering it to the clusterLinksFormatters dictionary.
   * @defaultValue standard
   * @see dashboardUrl
   * @example
   * ```ts
   * import { clusterLinksFormatters } from '@backstage/plugin-kubernetes';
   * clusterLinksFormatters.myDashboard = (options) => ...;
   * ```
   */
  dashboardApp?: string;
  /**
   * Specifies specific parameters used by some dashboard URL formatters.
   * This is used by the GKE formatter which requires the project, region and cluster name.
   * @see dashboardApp
   */
  dashboardParameters?: JsonObject;
  /**
   * Specifies which custom resources to look for when returning an entity's
   * Kubernetes resources.
   */
  customResources?: CustomResourceMatcher[];
}

/**
 *
 * @public
 */
export interface KubernetesObjectsProviderOptions {
  logger: Logger;
  config: Config;
  fetcher: KubernetesFetcher;
  serviceLocator: KubernetesServiceLocator;
  customResources: CustomResource[];
  objectTypesToFetch?: ObjectToFetch[];
}

/**
 *
 * @public
 */
export type ObjectsByEntityRequest = KubernetesRequestBody;

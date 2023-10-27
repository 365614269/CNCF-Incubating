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
import { createExtensionPoint } from '@backstage/backend-plugin-api';
import {
  EntityProvider,
  CatalogProcessor,
  PlaceholderResolver,
  ScmLocationAnalyzer,
} from '@backstage/plugin-catalog-node';

/**
 * @alpha
 */
export interface CatalogProcessingExtensionPoint {
  addProcessor(
    ...processors: Array<CatalogProcessor | Array<CatalogProcessor>>
  ): void;
  addEntityProvider(
    ...providers: Array<EntityProvider | Array<EntityProvider>>
  ): void;
  addPlaceholderResolver(key: string, resolver: PlaceholderResolver): void;
}

/**
 * @alpha
 */
export const catalogProcessingExtensionPoint =
  createExtensionPoint<CatalogProcessingExtensionPoint>({
    id: 'catalog.processing',
  });

/**
 * @alpha
 */
export interface CatalogAnalysisExtensionPoint {
  addLocationAnalyzer(analyzer: ScmLocationAnalyzer): void;
}

/**
 * @alpha
 */
export const catalogAnalysisExtensionPoint =
  createExtensionPoint<CatalogAnalysisExtensionPoint>({
    id: 'catalog.analysis',
  });

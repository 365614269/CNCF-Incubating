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

import { Extension } from './createExtension';
import { ExternalRouteRef, RouteRef } from '../routing';

/** @public */
export type AnyRoutes = { [name in string]: RouteRef };

/** @public */
export type AnyExternalRoutes = { [name in string]: ExternalRouteRef };

/** @public */
export interface PluginOptions<
  Routes extends AnyRoutes,
  ExternalRoutes extends AnyExternalRoutes,
> {
  id: string;
  routes?: Routes;
  externalRoutes?: ExternalRoutes;
  extensions?: Extension<unknown>[];
}

/** @public */
export interface BackstagePlugin<
  Routes extends AnyRoutes = AnyRoutes,
  ExternalRoutes extends AnyExternalRoutes = AnyExternalRoutes,
> {
  $$type: '@backstage/BackstagePlugin';
  id: string;
  extensions: Extension<unknown>[];
  routes: Routes;
  externalRoutes: ExternalRoutes;
}

/** @public */
export function createPlugin<
  Routes extends AnyRoutes = {},
  ExternalRoutes extends AnyExternalRoutes = {},
>(
  options: PluginOptions<Routes, ExternalRoutes>,
): BackstagePlugin<Routes, ExternalRoutes> {
  return {
    ...options,
    routes: options.routes ?? ({} as Routes),
    externalRoutes: options.externalRoutes ?? ({} as ExternalRoutes),
    extensions: options.extensions ?? [],
    $$type: '@backstage/BackstagePlugin',
  };
}

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

import React, { lazy } from 'react';
import { ExtensionBoundary } from '../components';
import { createSchemaFromZod, PortableSchema } from '../schema';
import {
  coreExtensionData,
  createExtension,
  Extension,
  ExtensionInputValues,
  AnyExtensionInputMap,
} from '../wiring';
import { RouteRef } from '../routing';
import { Expand } from '../types';

/**
 * Helper for creating extensions for a routable React page component.
 *
 * @public
 */
export function createPageExtension<
  TConfig extends { path: string },
  TInputs extends AnyExtensionInputMap,
>(
  options: (
    | {
        defaultPath: string;
      }
    | {
        configSchema: PortableSchema<TConfig>;
      }
  ) & {
    id: string;
    attachTo?: { id: string; input: string };
    disabled?: boolean;
    inputs?: TInputs;
    routeRef?: RouteRef;
    loader: (options: {
      config: TConfig;
      inputs: Expand<ExtensionInputValues<TInputs>>;
    }) => Promise<JSX.Element>;
  },
): Extension<TConfig> {
  const { id } = options;

  const configSchema =
    'configSchema' in options
      ? options.configSchema
      : (createSchemaFromZod(z =>
          z.object({ path: z.string().default(options.defaultPath) }),
        ) as PortableSchema<TConfig>);

  return createExtension({
    id,
    attachTo: options.attachTo ?? { id: 'core.routes', input: 'routes' },
    configSchema,
    inputs: options.inputs,
    disabled: options.disabled,
    output: {
      element: coreExtensionData.reactElement,
      path: coreExtensionData.routePath,
      routeRef: coreExtensionData.routeRef.optional(),
    },
    factory({ config, inputs, source }) {
      const ExtensionComponent = lazy(() =>
        options
          .loader({ config, inputs })
          .then(element => ({ default: () => element })),
      );

      return {
        path: config.path,
        routeRef: options.routeRef,
        element: (
          <ExtensionBoundary id={id} source={source} routable>
            <ExtensionComponent />
          </ExtensionBoundary>
        ),
      };
    },
  });
}

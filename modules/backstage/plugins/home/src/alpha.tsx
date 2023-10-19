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

import React from 'react';

import {
  coreExtensionData,
  createExtensionDataRef,
  createExtensionInput,
  createPageExtension,
  createPlugin,
  createRouteRef,
} from '@backstage/frontend-plugin-api';

const rootRouteRef = createRouteRef();

/**
 * @alpha
 */
export const titleExtensionDataRef = createExtensionDataRef<string>('title');

const HomepageCompositionRootExtension = createPageExtension({
  id: 'home',
  defaultPath: '/home',
  routeRef: rootRouteRef,
  inputs: {
    props: createExtensionInput(
      {
        children: coreExtensionData.reactElement.optional(),
        title: titleExtensionDataRef.optional(),
      },

      {
        singleton: true,
        optional: true,
      },
    ),
  },
  loader: ({ inputs }) =>
    import('./components/').then(m => (
      <m.HomepageCompositionRoot
        children={inputs.props?.children}
        title={inputs.props?.title}
      />
    )),
});

/**
 * @alpha
 */
export default createPlugin({
  id: 'home',
  extensions: [HomepageCompositionRootExtension],
});

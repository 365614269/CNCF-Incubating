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
import { renderWithEffects, wrapInTestApp } from '@backstage/test-utils';
import { useAnalytics } from '@backstage/core-plugin-api';
import { waitFor } from '@testing-library/react';
import { PortableSchema } from '../schema';
import {
  coreExtensionData,
  createExtensionInput,
  createPlugin,
} from '../wiring';
import { createPageExtension } from './createPageExtension';

jest.mock('@backstage/core-plugin-api', () => ({
  ...jest.requireActual('@backstage/core-plugin-api'),
  useAnalytics: jest.fn(),
}));

describe('createPageExtension', () => {
  it('creates the extension properly', () => {
    const configSchema: PortableSchema<{ path: string }> = {
      parse: jest.fn(),
      schema: {} as any,
    };

    expect(
      createPageExtension({
        id: 'test',
        configSchema,
        loader: async () => <div />,
      }),
    ).toEqual({
      $$type: '@backstage/Extension',
      id: 'test',
      attachTo: { id: 'core.routes', input: 'routes' },
      configSchema: expect.anything(),
      disabled: false,
      inputs: {},
      output: {
        element: expect.anything(),
        path: expect.anything(),
        routeRef: expect.anything(),
      },
      factory: expect.any(Function),
    });

    expect(
      createPageExtension({
        id: 'test',
        attachTo: { id: 'other', input: 'place' },
        disabled: true,
        configSchema,
        inputs: {
          first: createExtensionInput({
            element: coreExtensionData.reactElement,
          }),
        },
        loader: async () => <div />,
      }),
    ).toEqual({
      $$type: '@backstage/Extension',
      id: 'test',
      attachTo: { id: 'other', input: 'place' },
      configSchema: expect.anything(),
      disabled: true,
      inputs: {
        first: createExtensionInput({
          element: coreExtensionData.reactElement,
        }),
      },
      output: {
        element: expect.anything(),
        path: expect.anything(),
        routeRef: expect.anything(),
      },
      factory: expect.any(Function),
    });

    expect(
      createPageExtension({
        id: 'test',
        defaultPath: '/here',
        loader: async () => <div />,
      }),
    ).toEqual({
      $$type: '@backstage/Extension',
      id: 'test',
      attachTo: { id: 'core.routes', input: 'routes' },
      configSchema: expect.anything(),
      disabled: false,
      inputs: {},
      output: {
        element: expect.anything(),
        path: expect.anything(),
        routeRef: expect.anything(),
      },
      factory: expect.any(Function),
    });
  });

  it('capture page view event in analytics', async () => {
    const captureEvent = jest.fn();

    (useAnalytics as jest.Mock).mockReturnValue({
      captureEvent,
    });

    const extension = createPageExtension({
      id: 'plugin.page',
      defaultPath: '/',
      loader: async () => <div>Component</div>,
    });

    const output = extension.factory({
      source: createPlugin({ id: 'plugin ' }),
      config: { path: '/' },
      inputs: {},
    });

    renderWithEffects(wrapInTestApp(output.element as unknown as JSX.Element));

    await waitFor(() =>
      expect(captureEvent).toHaveBeenCalledWith(
        '_ROUTABLE-EXTENSION-RENDERED',
        '',
      ),
    );
  });
});

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
import React from 'react';
import { renderHook, act } from '@testing-library/react-hooks';

import { ThemeProvider } from '@material-ui/core';

import { lightTheme } from '@backstage/theme';
import { MockAnalyticsApi, TestApiProvider } from '@backstage/test-utils';
import { Entity, CompoundEntityRef } from '@backstage/catalog-model';
import {
  analyticsApiRef,
  configApiRef,
  useAnalytics,
} from '@backstage/core-plugin-api';

import { techdocsApiRef } from './api';
import { useTechDocsReaderPage, TechDocsReaderPageProvider } from './context';
import { TechDocsMetadata } from './types';

const mockShadowRoot = () => {
  const div = document.createElement('div');
  const shadowRoot = div.attachShadow({ mode: 'open' });
  shadowRoot.innerHTML = '<h1>Shadow DOM Mock</h1>';
  return shadowRoot;
};

const mockEntityMetadata: Entity = {
  apiVersion: 'v1',
  kind: 'Component',
  metadata: {
    name: 'test',
    namespace: 'default',
  },
  spec: {
    owner: 'test',
  },
};

const mockTechDocsMetadata: TechDocsMetadata = {
  site_name: 'test-componnet',
  site_description: 'this is a test component',
};

const techdocsApiMock = {
  getEntityMetadata: jest.fn().mockResolvedValue(mockEntityMetadata),
  getTechDocsMetadata: jest.fn().mockResolvedValue(mockTechDocsMetadata),
};

const configApiMock = {
  getOptionalBoolean: jest.fn().mockReturnValue(undefined),
};

const analyticsApiMock = new MockAnalyticsApi();

const wrapper = ({
  entityRef = {
    kind: mockEntityMetadata.kind,
    name: mockEntityMetadata.metadata.name,
    namespace: mockEntityMetadata.metadata.namespace!!,
  },
  children,
}: {
  entityRef?: CompoundEntityRef;
  children: React.ReactNode;
}) => (
  <ThemeProvider theme={lightTheme}>
    <TestApiProvider
      apis={[
        [analyticsApiRef, analyticsApiMock],
        [configApiRef, configApiMock],
        [techdocsApiRef, techdocsApiMock],
      ]}
    >
      <TechDocsReaderPageProvider entityRef={entityRef}>
        {children}
      </TechDocsReaderPageProvider>
    </TestApiProvider>
  </ThemeProvider>
);

describe('useTechDocsReaderPage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should set title', async () => {
    const { result, waitForNextUpdate } = renderHook(
      () => useTechDocsReaderPage(),
      { wrapper },
    );

    expect(result.current.title).toBe('');

    act(() => result.current.setTitle('test site title'));

    await waitForNextUpdate();

    expect(result.current.title).toBe('test site title');
  });

  it('should set subtitle', async () => {
    const { result, waitForNextUpdate } = renderHook(
      () => useTechDocsReaderPage(),
      { wrapper },
    );

    expect(result.current.subtitle).toBe('');

    act(() => result.current.setSubtitle('test site subtitle'));

    await waitForNextUpdate();

    expect(result.current.subtitle).toBe('test site subtitle');
  });

  it('should set shadow root', async () => {
    const { result, waitForNextUpdate } = renderHook(
      () => useTechDocsReaderPage(),
      { wrapper },
    );

    // mock shadowroot
    const shadowRoot = mockShadowRoot();

    act(() => result.current.setShadowRoot(shadowRoot));

    await waitForNextUpdate();

    expect(result.current.shadowRoot?.innerHTML).toBe(
      '<h1>Shadow DOM Mock</h1>',
    );
  });

  it('should set entityRef as lowercase when legacyUseCaseSensitiveTripletPaths is false', async () => {
    const lowercaseEntityRef = {
      kind: mockEntityMetadata.kind.toLocaleLowerCase(),
      name: mockEntityMetadata.metadata.name.toLocaleLowerCase(),
      namespace: mockEntityMetadata.metadata.namespace?.toLocaleLowerCase(),
    };
    const { result } = renderHook(() => useTechDocsReaderPage(), { wrapper });

    expect(result.current.entityRef).toStrictEqual(lowercaseEntityRef);
  });

  it('entityRef is not modified when legacyUseCaseSensitiveTripletPaths is true', async () => {
    configApiMock.getOptionalBoolean.mockReturnValueOnce(true);
    const caseSensitiveEntityRef = {
      kind: mockEntityMetadata.kind,
      name: mockEntityMetadata.metadata.name,
      namespace: mockEntityMetadata.metadata.namespace!!,
    };

    const { result } = renderHook(() => useTechDocsReaderPage(), { wrapper });

    expect(result.current.entityRef).toStrictEqual(caseSensitiveEntityRef);
  });

  it('entityRef provided as analytics context', async () => {
    const { waitForNextUpdate } = renderHook(
      () => useAnalytics().captureEvent('action', 'subject'),
      { wrapper },
    );

    await waitForNextUpdate();

    expect(analyticsApiMock.getEvents()[0]).toMatchObject({
      action: 'action',
      subject: 'subject',
      context: {
        entityRef: 'component:default/test',
      },
    });
  });
});

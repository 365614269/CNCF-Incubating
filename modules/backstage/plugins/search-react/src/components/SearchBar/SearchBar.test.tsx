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
import { screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { configApiRef, analyticsApiRef } from '@backstage/core-plugin-api';
import { ConfigReader } from '@backstage/core-app-api';
import {
  MockAnalyticsApi,
  TestApiProvider,
  renderWithEffects,
} from '@backstage/test-utils';
import { searchApiRef } from '../../api';
import { SearchContextProvider } from '../../context';
import { SearchBar } from './SearchBar';

const createInitialState = ({
  term = '',
  filters = {},
  types = ['*'],
  pageCursor = '',
} = {}) => ({
  term,
  filters,
  types,
  pageCursor,
});

describe('SearchBar', () => {
  const user = userEvent.setup({ delay: null });

  const query = jest.fn().mockResolvedValue({ results: [] });

  const searchApiMock = { query };

  const configApiMock = new ConfigReader({
    app: {
      title: 'Mock title',
      analytics: {
        ga: {
          trackingId: 'xyz123',
        },
      },
    },
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('Renders without exploding', async () => {
    await renderWithEffects(
      <TestApiProvider
        apis={[
          [configApiRef, configApiMock],
          [searchApiRef, searchApiMock],
        ]}
      >
        <SearchContextProvider>
          <SearchBar debounceTime={0} />
        </SearchContextProvider>
      </TestApiProvider>,
    );

    await waitFor(() =>
      expect(screen.getByLabelText('Search')).toBeInTheDocument(),
    );
  });

  it('Renders with custom label', async () => {
    const label = 'label';

    await renderWithEffects(
      <TestApiProvider
        apis={[
          [configApiRef, configApiMock],
          [searchApiRef, searchApiMock],
        ]}
      >
        <SearchContextProvider>
          <SearchBar label={label} debounceTime={0} />
        </SearchContextProvider>
      </TestApiProvider>,
    );

    await waitFor(() =>
      expect(screen.getByLabelText(label)).toBeInTheDocument(),
    );
  });

  it('Renders with custom placeholder', async () => {
    const placeholder = 'placeholder';

    await renderWithEffects(
      <TestApiProvider
        apis={[
          [configApiRef, configApiMock],
          [searchApiRef, searchApiMock],
        ]}
      >
        <SearchContextProvider>
          <SearchBar placeholder={placeholder} debounceTime={0} />
        </SearchContextProvider>
      </TestApiProvider>,
    );

    await waitFor(() =>
      expect(screen.getByPlaceholderText(placeholder)).toBeInTheDocument(),
    );
  });

  it('Renders based on initial search', async () => {
    const term = 'term';

    await renderWithEffects(
      <TestApiProvider
        apis={[
          [configApiRef, configApiMock],
          [searchApiRef, searchApiMock],
        ]}
      >
        <SearchContextProvider initialState={createInitialState({ term })}>
          <SearchBar debounceTime={0} />
        </SearchContextProvider>
      </TestApiProvider>,
    );

    await waitFor(() =>
      expect(screen.getByLabelText('Search')).toHaveValue(term),
    );
  });

  it('Updates term state when text is entered', async () => {
    jest.useFakeTimers();

    await renderWithEffects(
      <TestApiProvider
        apis={[
          [configApiRef, configApiMock],
          [searchApiRef, searchApiMock],
        ]}
      >
        <SearchContextProvider>
          <SearchBar />
        </SearchContextProvider>
      </TestApiProvider>,
    );

    const textbox = screen.getByLabelText('Search');

    const value = 'value';

    await user.type(textbox, value);

    act(() => {
      jest.advanceTimersByTime(200);
    });

    await waitFor(() => expect(textbox).toHaveValue(value));

    expect(query).toHaveBeenLastCalledWith(
      expect.objectContaining({ term: value }),
    );

    jest.runAllTimers();
    jest.useRealTimers();
  });

  it('Clear button clears term state', async () => {
    const term = 'term';

    await renderWithEffects(
      <TestApiProvider
        apis={[
          [configApiRef, configApiMock],
          [searchApiRef, searchApiMock],
        ]}
      >
        <SearchContextProvider initialState={createInitialState({ term })}>
          <SearchBar debounceTime={0} />
        </SearchContextProvider>
      </TestApiProvider>,
    );

    const textbox = screen.getByLabelText('Search');

    await waitFor(() => expect(textbox).toHaveValue(term));

    await user.click(screen.getByLabelText('Clear'));

    await waitFor(() => expect(textbox).toHaveValue(''));

    expect(query).toHaveBeenLastCalledWith(
      expect.objectContaining({ term: '' }),
    );
  });

  it('Should not show clear button', async () => {
    const term = 'term';

    await renderWithEffects(
      <TestApiProvider
        apis={[
          [configApiRef, configApiMock],
          [searchApiRef, searchApiMock],
        ]}
      >
        <SearchContextProvider initialState={createInitialState({ term })}>
          <SearchBar clearButton={false} debounceTime={0} />
        </SearchContextProvider>
      </TestApiProvider>,
    );

    await waitFor(() =>
      expect(screen.queryByLabelText('Clear')).not.toBeInTheDocument(),
    );
  });

  it('Adheres to provided debounceTime', async () => {
    jest.useFakeTimers();

    const debounceTime = 100;

    await renderWithEffects(
      <TestApiProvider
        apis={[
          [configApiRef, configApiMock],
          [searchApiRef, searchApiMock],
        ]}
      >
        <SearchContextProvider>
          <SearchBar debounceTime={debounceTime} />
        </SearchContextProvider>
      </TestApiProvider>,
    );

    const textbox = screen.getByLabelText('Search');

    const value = 'value';

    await user.type(textbox, value);

    await waitFor(() =>
      expect(query).not.toHaveBeenLastCalledWith(
        expect.objectContaining({ term: value }),
      ),
    );

    act(() => {
      jest.advanceTimersByTime(debounceTime);
    });

    await waitFor(() => expect(textbox).toHaveValue(value));

    expect(query).toHaveBeenLastCalledWith(
      expect.objectContaining({ term: value }),
    );

    jest.runAllTimers();
    jest.useRealTimers();
  });

  it('Does not capture analytics event if not enabled in app', async () => {
    const analyticsApiMock = new MockAnalyticsApi();

    await renderWithEffects(
      <TestApiProvider
        apis={[
          [configApiRef, configApiMock],
          [searchApiRef, searchApiMock],
        ]}
      >
        <SearchContextProvider>
          <SearchBar debounceTime={0} />
        </SearchContextProvider>
      </TestApiProvider>,
    );

    const textbox = screen.getByLabelText('Search');

    const value = 'value';

    await user.type(textbox, value);

    await waitFor(() => expect(textbox).toHaveValue(value));

    expect(analyticsApiMock.getEvents()).toHaveLength(0);
  });

  it('Captures analytics events if enabled in app', async () => {
    const analyticsApiMock = new MockAnalyticsApi();

    const types = ['techdocs', 'software-catalog'];

    await renderWithEffects(
      <TestApiProvider
        apis={[
          [configApiRef, configApiMock],
          [searchApiRef, searchApiMock],
          [analyticsApiRef, analyticsApiMock],
        ]}
      >
        <SearchContextProvider initialState={createInitialState({ types })}>
          <SearchBar debounceTime={0} />
        </SearchContextProvider>
      </TestApiProvider>,
    );

    const textbox = screen.getByLabelText('Search');

    let value = 'value';
    await user.type(textbox, value);
    await waitFor(() => {
      expect(analyticsApiMock.getEvents()).toHaveLength(1);
      expect(textbox).toHaveValue(value);
      expect(analyticsApiMock.getEvents()[0]).toEqual({
        action: 'search',
        context: {
          extension: 'SearchBar',
          pluginId: 'search',
          routeRef: 'unknown',
          searchTypes: types.toString(),
        },
        subject: value,
      });
    });

    value = 'new value';
    await user.clear(textbox);
    // make sure new term is captured
    await user.type(textbox, value);
    await waitFor(() => {
      expect(analyticsApiMock.getEvents()).toHaveLength(2);
      expect(textbox).toHaveValue(value);
      expect(analyticsApiMock.getEvents()[1]).toEqual({
        action: 'search',
        context: {
          extension: 'SearchBar',
          pluginId: 'search',
          routeRef: 'unknown',
          searchTypes: types.toString(),
        },
        subject: value,
      });
    });
  });
});

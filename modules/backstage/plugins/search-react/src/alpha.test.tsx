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

import { render, screen } from '@testing-library/react';

import {
  createExtensionInput,
  createPageExtension,
  createPlugin,
  createSchemaFromZod,
} from '@backstage/frontend-plugin-api';
import { SearchResult } from '@backstage/plugin-search-common';
import { createApp } from '@backstage/frontend-app-api';
import { MockConfigApi } from '@backstage/test-utils';

import {
  BaseSearchResultListItemProps,
  createSearchResultListItemExtension,
  searchResultItemExtensionData as searchResultListItemExtensionData,
} from './alpha';

// TODO: Remove this mock when we have a permanent solution for nav items extensions
// The `GraphiQLIcon` used in "packages/frontend-app-api/src/extensions/CoreNav.tsx" file
// is throwing a "ReferenceError: ref is not defined" error during test
jest.mock('@backstage/plugin-graphiql', () => ({
  ...jest.requireActual('@backstage/plugin-graphiql'),
  GraphiQLIcon: () => null,
}));

describe('createSearchResultListItemExtension', () => {
  it('Should use the correct result component', async () => {
    type TechDocsSearchReasulListItemProps = BaseSearchResultListItemProps<{
      lineClamp: number;
    }>;
    const TechDocsSearchResultItemComponent = (
      props: TechDocsSearchReasulListItemProps,
    ) => (
      <div>
        TechDocs - Rank: {props.rank} - Line clamp: {props.lineClamp}
      </div>
    );

    const TechDocsSearchResultItemExtension =
      createSearchResultListItemExtension({
        id: 'techdocs',
        attachTo: { id: 'plugin.search.page', input: 'items' },
        configSchema: createSchemaFromZod(z =>
          z.object({
            noTrack: z.boolean().default(true),
            lineClamp: z.number().default(5),
          }),
        ),
        predicate: result => result.type === 'techdocs',
        component:
          async ({ config }) =>
          props =>
            <TechDocsSearchResultItemComponent {...props} {...config} />,
      });

    const ExploreSearchResultItemComponent = (
      props: BaseSearchResultListItemProps,
    ) => <div>Explore - Rank: {props.rank}</div>;

    const ExploreSearchResultItemExtension =
      createSearchResultListItemExtension({
        id: 'explore',
        attachTo: { id: 'plugin.search.page', input: 'items' },
        predicate: result => result.type === 'explore',
        component: async () => ExploreSearchResultItemComponent,
      });

    const SearchPageExtension = createPageExtension({
      id: 'plugin.search.page',
      defaultPath: '/',
      inputs: {
        items: createExtensionInput({
          item: searchResultListItemExtensionData,
        }),
      },
      loader: async ({ inputs }) => {
        const results = [
          {
            type: 'techdocs',
            rank: 1,
            document: {
              title: 'Title1',
              text: 'Text1',
              location: '/location1',
            },
          },
          {
            type: 'explore',
            rank: 2,
            document: {
              title: 'Title2',
              text: 'Text2',
              location: '/location2',
            },
          },
          {
            type: 'other',
            rank: 3,
            document: {
              title: 'Title3',
              text: 'Text3',
              location: '/location3',
            },
          },
        ];

        const DefaultResultItem = (props: BaseSearchResultListItemProps) => (
          <div>Default - Rank: {props.rank}</div>
        );

        const getResultItemComponent = (result: SearchResult) => {
          const value = inputs.items.find(({ item }) =>
            item?.predicate?.(result),
          );
          return value?.item.component ?? DefaultResultItem;
        };

        const Component = () => {
          return (
            <div>
              <h1>Search Page</h1>
              <ul>
                {results.map((result, index) => {
                  const SearchResultListItem = getResultItemComponent(result);
                  return (
                    <SearchResultListItem
                      key={index}
                      rank={result.rank}
                      result={result.document}
                    />
                  );
                })}
              </ul>
            </div>
          );
        };

        return <Component />;
      },
    });

    const SearchPlugin = createPlugin({
      id: 'search.plugin',
      extensions: [
        SearchPageExtension,
        ExploreSearchResultItemExtension,
        TechDocsSearchResultItemExtension,
      ],
    });

    const app = createApp({
      features: [SearchPlugin],
      configLoader: async () =>
        new MockConfigApi({
          app: {
            extensions: [
              {
                'plugin.search.result.item.techdocs': {
                  config: {
                    lineClamp: 3,
                  },
                },
              },
            ],
          },
        }),
    });

    render(app.createRoot());

    expect(await screen.findByText(/Search Page/)).toBeInTheDocument();

    expect(
      await screen.findByText(/TechDocs - Rank: 1 - Line clamp: 3/, {
        exact: false,
      }),
    ).toBeInTheDocument();

    expect(
      await screen.findByText(/Explore - Rank: 2/, { exact: false }),
    ).toBeInTheDocument();

    expect(
      await screen.findByText(/Default - Rank: 3/, { exact: false }),
    ).toBeInTheDocument();
  });
});

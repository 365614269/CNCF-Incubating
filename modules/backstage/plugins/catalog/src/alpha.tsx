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

import {
  createApiFactory,
  discoveryApiRef,
  fetchApiRef,
  storageApiRef,
} from '@backstage/core-plugin-api';
import { CatalogClient } from '@backstage/catalog-client';
import {
  createApiExtension,
  createPlugin,
} from '@backstage/frontend-plugin-api';
import {
  catalogApiRef,
  starredEntitiesApiRef,
} from '@backstage/plugin-catalog-react';
import { createSearchResultListItemExtension } from '@backstage/plugin-search-react/alpha';
import { DefaultStarredEntitiesApi } from './apis';

/** @alpha */
export const CatalogApi = createApiExtension({
  factory: createApiFactory({
    api: catalogApiRef,
    deps: {
      discoveryApi: discoveryApiRef,
      fetchApi: fetchApiRef,
    },
    factory: ({ discoveryApi, fetchApi }) =>
      new CatalogClient({ discoveryApi, fetchApi }),
  }),
});

/** @alpha */
export const StarredEntitiesApi = createApiExtension({
  factory: createApiFactory({
    api: starredEntitiesApiRef,
    deps: { storageApi: storageApiRef },
    factory: ({ storageApi }) => new DefaultStarredEntitiesApi({ storageApi }),
  }),
});

/** @alpha */
export const CatalogSearchResultListItemExtension =
  createSearchResultListItemExtension({
    id: 'catalog',
    predicate: result => result.type === 'software-catalog',
    component: () =>
      import('./components/CatalogSearchResultListItem').then(
        m => m.CatalogSearchResultListItem,
      ),
  });

/** @alpha */
export default createPlugin({
  id: 'catalog',
  extensions: [
    CatalogApi,
    StarredEntitiesApi,
    CatalogSearchResultListItemExtension,
  ],
});

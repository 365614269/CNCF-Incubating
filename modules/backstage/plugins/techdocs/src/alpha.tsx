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
import LibraryBooks from '@material-ui/icons/LibraryBooks';
import {
  createPlugin,
  createSchemaFromZod,
  createApiExtension,
  createPageExtension,
  createNavItemExtension,
} from '@backstage/frontend-plugin-api';
import { createSearchResultListItemExtension } from '@backstage/plugin-search-react/alpha';
import {
  configApiRef,
  createApiFactory,
  discoveryApiRef,
  fetchApiRef,
  identityApiRef,
} from '@backstage/core-plugin-api';
import { convertLegacyRouteRef } from '@backstage/core-plugin-api/alpha';
import {
  techdocsApiRef,
  techdocsStorageApiRef,
} from '@backstage/plugin-techdocs-react';
import { TechDocsClient, TechDocsStorageClient } from './client';
import {
  rootCatalogDocsRouteRef,
  rootDocsRouteRef,
  rootRouteRef,
} from './routes';
import { createEntityContentExtension } from '@backstage/plugin-catalog-react/alpha';

/** @alpha */
const techDocsStorage = createApiExtension({
  api: techdocsStorageApiRef,

  factory() {
    return createApiFactory({
      api: techdocsStorageApiRef,
      deps: {
        configApi: configApiRef,
        discoveryApi: discoveryApiRef,
        identityApi: identityApiRef,
        fetchApi: fetchApiRef,
      },
      factory: ({ configApi, discoveryApi, identityApi, fetchApi }) =>
        new TechDocsStorageClient({
          configApi,
          discoveryApi,
          identityApi,
          fetchApi,
        }),
    });
  },
});

/** @alpha */
const techDocsClient = createApiExtension({
  api: techdocsApiRef,
  factory() {
    return createApiFactory({
      api: techdocsApiRef,
      deps: {
        configApi: configApiRef,
        discoveryApi: discoveryApiRef,
        fetchApi: fetchApiRef,
      },
      factory: ({ configApi, discoveryApi, fetchApi }) =>
        new TechDocsClient({
          configApi,
          discoveryApi,
          fetchApi,
        }),
    });
  },
});

/** @alpha */
export const TechDocsSearchResultListItemExtension =
  createSearchResultListItemExtension({
    id: 'techdocs',
    configSchema: createSchemaFromZod(z =>
      z.object({
        // TODO: Define how the icon can be configurable
        title: z.string().optional(),
        lineClamp: z.number().default(5),
        asLink: z.boolean().default(true),
        asListItem: z.boolean().default(true),
        noTrack: z.boolean().default(false),
      }),
    ),
    predicate: result => result.type === 'techdocs',
    component: async ({ config }) => {
      const { TechDocsSearchResultListItem } = await import(
        './search/components/TechDocsSearchResultListItem'
      );
      return props => <TechDocsSearchResultListItem {...props} {...config} />;
    },
  });

/**
 * Responsible for rendering the provided router element
 *
 * @alpha
 */
const TechDocsIndexPage = createPageExtension({
  id: 'plugin.techdocs.indexPage',
  defaultPath: '/docs',
  routeRef: convertLegacyRouteRef(rootRouteRef),
  loader: () =>
    import('./home/components/TechDocsIndexPage').then(m => (
      <m.TechDocsIndexPage />
    )),
});

/**
 * Component responsible for composing a TechDocs reader page experience
 *
 * @alpha
 */
const TechDocsReaderPage = createPageExtension({
  id: 'plugin.techdocs.readerPage',
  defaultPath: '/docs/:namespace/:kind/:name',
  routeRef: convertLegacyRouteRef(rootDocsRouteRef),
  loader: () =>
    import('./reader/components/TechDocsReaderPage').then(m => (
      <m.TechDocsReaderPage />
    )),
});

/**
 * Component responsible for rendering techdocs on entity pages
 *
 * @alpha
 */
const TechDocsEntityContent = createEntityContentExtension({
  id: 'techdocs',
  defaultPath: 'docs',
  defaultTitle: 'TechDocs',
  loader: () => import('./Router').then(m => <m.EmbeddedDocsRouter />),
});

/** @alpha */
const TechDocsNavItem = createNavItemExtension({
  id: 'plugin.techdocs.nav.index',
  icon: LibraryBooks,
  title: 'Docs',
  routeRef: convertLegacyRouteRef(rootRouteRef),
});

/** @alpha */
export default createPlugin({
  id: 'techdocs',
  extensions: [
    techDocsClient,
    techDocsStorage,
    TechDocsNavItem,
    TechDocsIndexPage,
    TechDocsReaderPage,
    TechDocsEntityContent,
    TechDocsSearchResultListItemExtension,
  ],
  routes: {
    root: convertLegacyRouteRef(rootRouteRef),
    docRoot: convertLegacyRouteRef(rootDocsRouteRef),
    entityContent: convertLegacyRouteRef(rootCatalogDocsRouteRef),
  },
});

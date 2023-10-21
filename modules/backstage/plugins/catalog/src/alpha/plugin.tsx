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
import HomeIcon from '@material-ui/icons/Home';
import {
  createApiFactory,
  discoveryApiRef,
  fetchApiRef,
  storageApiRef,
} from '@backstage/core-plugin-api';
import { convertLegacyRouteRef } from '@backstage/core-plugin-api/alpha';
import { CatalogClient } from '@backstage/catalog-client';
import {
  createApiExtension,
  createPageExtension,
  createPlugin,
  createNavItemExtension,
  coreExtensionData,
  createExtensionInput,
} from '@backstage/frontend-plugin-api';
import {
  AsyncEntityProvider,
  catalogApiRef,
  entityRouteRef,
  starredEntitiesApiRef,
} from '@backstage/plugin-catalog-react';
import {
  createEntityContentExtension,
  createEntityCardExtension,
  entityContentTitleExtensionDataRef,
} from '@backstage/plugin-catalog-react/alpha';
import { createSearchResultListItemExtension } from '@backstage/plugin-search-react/alpha';
import { DefaultStarredEntitiesApi } from '../apis';
import {
  createComponentRouteRef,
  createFromTemplateRouteRef,
  rootRouteRef,
  viewTechDocRouteRef,
} from '../routes';
import { builtInFilterExtensions } from './builtInFilterExtensions';
import { useEntityFromUrl } from '../components/CatalogEntityPage/useEntityFromUrl';
import Grid from '@material-ui/core/Grid';

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
      import('../components/CatalogSearchResultListItem').then(
        m => m.CatalogSearchResultListItem,
      ),
  });

const CatalogIndexPage = createPageExtension({
  id: 'plugin.catalog.page.index',
  defaultPath: '/catalog',
  routeRef: convertLegacyRouteRef(rootRouteRef),
  inputs: {
    filters: createExtensionInput({
      element: coreExtensionData.reactElement,
    }),
  },
  loader: async ({ inputs }) => {
    const { BaseCatalogPage } = await import('../components/CatalogPage');
    const filters = inputs.filters.map(filter => filter.element);
    return <BaseCatalogPage filters={<>{filters}</>} />;
  },
});

const CatalogEntityPage = createPageExtension({
  id: 'plugin.catalog.page.entity',
  defaultPath: '/catalog/:namespace/:kind/:name',
  routeRef: convertLegacyRouteRef(entityRouteRef),
  inputs: {
    contents: createExtensionInput({
      element: coreExtensionData.reactElement,
      path: coreExtensionData.routePath,
      routeRef: coreExtensionData.routeRef.optional(),
      title: entityContentTitleExtensionDataRef,
    }),
  },
  loader: async ({ inputs }) => {
    const { EntityLayout } = await import('../components/EntityLayout');
    const Component = () => {
      return (
        <AsyncEntityProvider {...useEntityFromUrl()}>
          <EntityLayout>
            {inputs.contents.map(content => (
              <EntityLayout.Route
                key={content.path}
                path={content.path}
                title={content.title}
              >
                {content.element}
              </EntityLayout.Route>
            ))}
          </EntityLayout>
        </AsyncEntityProvider>
      );
    };
    return <Component />;
  },
});

const EntityAboutCard = createEntityCardExtension({
  id: 'about',
  loader: async () =>
    import('../components/AboutCard').then(m => (
      <m.AboutCard variant="gridItem" />
    )),
});

const OverviewEntityContent = createEntityContentExtension({
  id: 'overview',
  defaultPath: '/',
  defaultTitle: 'Overview',
  disabled: false,
  inputs: {
    cards: createExtensionInput({
      element: coreExtensionData.reactElement,
    }),
  },
  loader: async ({ inputs }) => (
    <Grid container spacing={3} alignItems="stretch">
      {inputs.cards.map(card => (
        <Grid item md={6} xs={12}>
          {card.element}
        </Grid>
      ))}
    </Grid>
  ),
});

const CatalogNavItem = createNavItemExtension({
  id: 'catalog.nav.index',
  routeRef: convertLegacyRouteRef(rootRouteRef),
  title: 'Catalog',
  icon: HomeIcon,
});

/** @alpha */
export default createPlugin({
  id: 'catalog',
  routes: {
    catalogIndex: convertLegacyRouteRef(rootRouteRef),
    catalogEntity: convertLegacyRouteRef(entityRouteRef),
  },
  externalRoutes: {
    viewTechDoc: convertLegacyRouteRef(viewTechDocRouteRef),
    createComponent: convertLegacyRouteRef(createComponentRouteRef),
    createFromTemplate: convertLegacyRouteRef(createFromTemplateRouteRef),
  },
  extensions: [
    CatalogApi,
    StarredEntitiesApi,
    CatalogSearchResultListItemExtension,
    CatalogIndexPage,
    CatalogEntityPage,
    CatalogNavItem,
    OverviewEntityContent,
    EntityAboutCard,
    ...builtInFilterExtensions,
  ],
});

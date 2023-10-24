---
id: how-to-guides
title: Search How-To guides
sidebar_label: How-To guides
description: Search How To guides
---

## How to implement your own Search API

The Search plugin provides implementation of one primary API by default: the
[SearchApi](https://github.com/backstage/backstage/blob/db2666b980853c281b8fe77905d7639c5d255f13/plugins/search/src/apis.ts#L35),
which is responsible for talking to the search-backend to query search results.

There may be occasions where you need to implement this API yourself, to
customize it to your own needs - for example if you have your own search backend
that you want to talk to. The purpose of this guide is to walk you through how
to do that in two steps.

1. Implement the `SearchApi`
   [interface](https://github.com/backstage/backstage/blob/db2666b980853c281b8fe77905d7639c5d255f13/plugins/search/src/apis.ts#L31)
   according to your needs.

   ```typescript
   export class SearchClient implements SearchApi {
     // your implementation
   }
   ```

2. Override the API ref `searchApiRef` with your new implemented API in the
   `App.tsx` using `ApiFactories`.
   [Read more about App APIs](https://backstage.io/docs/api/utility-apis#app-apis).

   ```typescript
   const app = createApp({
     apis: [
       // SearchApi
       createApiFactory({
         api: searchApiRef,
         deps: { discovery: discoveryApiRef },
         factory({ discovery }) {
           return new SearchClient({ discoveryApi: discovery });
         },
       }),
     ],
   });
   ```

## How to index TechDocs documents

The TechDocs plugin has supported integrations to Search, meaning that it
provides a default collator factory ready to be used.

The purpose of this guide is to walk you through how to register the
[DefaultTechDocsCollatorFactory](https://github.com/backstage/backstage/blob/1adc2c7/plugins/search-backend-module-techdocs/src/collators/DefaultTechDocsCollatorFactory.ts)
in your App, so that you can get TechDocs documents indexed.

If you have been through the
[Getting Started with Search guide](https://backstage.io/docs/features/search/getting-started),
you should have the `packages/backend/src/plugins/search.ts` file available. If
so, you can go ahead and follow this guide - if not, start by going through the
getting started guide.

1. Import the `DefaultTechDocsCollatorFactory` from
   `@backstage/plugin-search-backend-module-techdocs`.

   ```typescript
   import { DefaultTechDocsCollatorFactory } from '@backstage/plugin-search-backend-module-techdocs';
   ```

2. If there isn't an existing schedule you'd like to run the collator on, be
   sure to create it first. Something like...

   ```typescript
   import { Duration } from 'luxon';

   const every10MinutesSchedule = env.scheduler.createScheduledTaskRunner({
     frequency: Duration.fromObject({ seconds: 600 }),
     timeout: Duration.fromObject({ seconds: 900 }),
     initialDelay: Duration.fromObject({ seconds: 3 }),
   });
   ```

3. Register the `DefaultTechDocsCollatorFactory` with the IndexBuilder.

   ```typescript
   indexBuilder.addCollator({
     schedule: every10MinutesSchedule,
     factory: DefaultTechDocsCollatorFactory.fromConfig(env.config, {
       discovery: env.discovery,
       logger: env.logger,
       tokenManager: env.tokenManager,
     }),
   });
   ```

You should now have your TechDocs documents indexed to your search engine of
choice!

If you want your users to be able to filter down to the techdocs type when
searching, you can update your `SearchPage.tsx` file in
`packages/app/src/components/search` by adding `techdocs` to the list of values
of the `SearchType` component.

```tsx title="packages/app/src/components/search/SearchPage.tsx"
<Paper className={classes.filters}>
  <SearchType
    values={['techdocs', 'software-catalog']}
    name="type"
    defaultValue="software-catalog"
  />
  {/* ... */}
</Paper>
```

> Check out the documentation around [integrating search into plugins](../../plugins/integrating-search-into-plugins.md#create-a-collator) for how to create your own collator.

## How to customize fields in the Software Catalog or TechDocs index

Sometimes, you might want to have the ability to control which data passes into the search index
in the catalog collator or customize data for a specific kind. You can easily achieve this
by passing an `entityTransformer` callback to the `DefaultCatalogCollatorFactory`. This behavior
is also possible for the `DefaultTechDocsCollatorFactory`. You can either simply amend the default behavior
or even write an entirely new document (which should still follow some required basic structure).

> `authorization` and `location` cannot be modified via a `entityTransformer`, `location` can be modified only through `locationTemplate`.

```ts title="packages/backend/src/plugins/search.ts"
const catalogEntityTransformer: CatalogCollatorEntityTransformer = (
  entity: Entity,
) => {
  if (entity.kind === 'SomeKind') {
    return {
      // customize here output for 'SomeKind' kind
    };
  }

  return {
    // and customize default output
    ...defaultCatalogCollatorEntityTransformer(entity),
    text: 'my super cool text',
  };
};

indexBuilder.addCollator({
  collator: DefaultCatalogCollatorFactory.fromConfig(env.config, {
    discovery: env.discovery,
    tokenManager: env.tokenManager,
    /* highlight-add-next-line */
    entityTransformer: catalogEntityTransformer,
  }),
});

const techDocsEntityTransformer: TechDocsCollatorEntityTransformer = (
  entity: Entity,
) => {
  return {
    // add more fields to the index
    ...defaultTechDocsCollatorEntityTransformer(entity),
    tags: entity.metadata.tags,
  };
};

indexBuilder.addCollator({
  collator: DefaultTechDocsCollatorFactory.fromConfig(env.config, {
    discovery: env.discovery,
    tokenManager: env.tokenManager,
    /* highlight-add-next-line */
    entityTransformer: techDocsEntityTransformer,
  }),
});
```

## How to limit what can be searched in the Software Catalog

The Software Catalog includes a wealth of information about the components,
systems, groups, users, and other aspects of your software ecosystem. However,
you may not always want _every_ aspect to appear when a user searches the
catalog. Examples include:

- Entities of kind `Location`, which are often not useful to Backstage users.
- Entities of kind `User` or `Group`, if you'd prefer that users and groups be
  exposed to search in a different way (or not at all).

It's possible to write your own [Collator](./concepts.md#collators) to control
exactly what's available to search, (or a [Decorator](./concepts.md#decorators)
to filter things out here and there), but the `DefaultCatalogCollator` that's
provided by `@backstage/plugin-catalog-backend` offers some configuration too!

```ts title="packages/backend/src/plugins/search.ts"
indexBuilder.addCollator({
  defaultRefreshIntervalSeconds: 600,
  collator: DefaultCatalogCollator.fromConfig(env.config, {
    discovery: env.discovery,
    tokenManager: env.tokenManager,
    /* highlight-add-start */
    filter: {
      kind: ['API', 'Component', 'Domain', 'Group', 'System', 'User'],
    },
    /* highlight-add-end */
  }),
});
```

As shown above, you can add a catalog entity filter to narrow down what catalog
entities are indexed by the search engine.

## How to customize search results highlighting styling

The default highlighting styling for matched terms in search results is your
browsers default styles for the `<mark>` HTML tag. If you want to customize
how highlighted terms look you can follow Backstage's guide on how to
[Customize the look-and-feel of your App](https://backstage.io/docs/getting-started/app-custom-theme)
to create an override with your preferred styling.

For example, the following will result in highlighted terms to be bold & underlined:

```tsx
const highlightOverride = {
  BackstageHighlightedSearchResultText: {
    highlight: {
      color: 'inherit',
      backgroundColor: 'inherit',
      fontWeight: 'bold',
      textDecoration: 'underline',
    },
  },
};
```

## How to render search results using extensions

Extensions for search results let you customize components used to render search result items, It is possible to provide your own search result item extensions or use the ones provided by plugin packages:

### 1. Providing an extension in your plugin package

Using the example below, you can provide an extension to be used as a default result item:

```tsx title="plugins/your-plugin/src/plugin.ts"
import { createPlugin } from '@backstage/core-plugin-api';
import { createSearchResultListItemExtension } from '@backstage/plugin-search-react';

const plugin = createPlugin({ id: 'YOUR_PLUGIN_ID' });

export const YourSearchResultListItemExtension = plugin.provide(
  createSearchResultListItemExtension({
    name: 'YourSearchResultListItem',
    component: () =>
      import('./components').then(m => m.YourSearchResultListItem),
  }),
);
```

If your list item accept props, you can extend the `SearchResultListItemExtensionProps` with your component specific props:

```tsx
export const YourSearchResultListItemExtension: (
  props: SearchResultListItemExtensionProps<YourSearchResultListItemProps>,
) => JSX.Element | null = plugin.provide(
  createSearchResultListItemExtension({
    name: 'YourSearchResultListItem',
    component: () =>
      import('./components').then(m => m.YourSearchResultListItem),
  }),
);
```

Additionally, you can define a predicate function that receives a result and returns whether your extension should be used to render it or not:

```tsx title="plugins/your-plugin/src/plugin.ts"
import { createPlugin } from '@backstage/core-plugin-api';
import { createSearchResultListItemExtension } from '@backstage/plugin-search-react';

const plugin = createPlugin({ id: 'YOUR_PLUGIN_ID' });

export const YourSearchResultListItemExtension = plugin.provide(
  createSearchResultListItemExtension({
    name: 'YourSearchResultListItem',
    component: () =>
      import('./components').then(m => m.YourSearchResultListItem),
    // Only results matching your type will be rendered by this extension
    predicate: result => result.type === 'YOUR_RESULT_TYPE',
  }),
);
```

Remember to export your new extension:

```tsx title="plugins/your-plugin/src/index.ts"
export { YourSearchResultListItem } from './plugin.ts';
```

For more details, see the [createSearchResultListItemExtension](https://backstage.io/docs/reference/plugin-search-react.createsearchresultlistitemextension) API reference.

### 2. Using an extension in your Backstage app

Now that you know how a search result item is provided, let's finally see how they can be used, for example, to compose a page in your application:

```tsx title="packages/app/src/components/searchPage.tsx"
import React from 'react';

import { Grid, Paper } from '@material-ui/core';
import BuildIcon from '@material-ui/icons/Build';

import {
  Page,
  Header,
  Content,
  DocsIcon,
  CatalogIcon,
} from '@backstage/core-components';
import { SearchBar, SearchResult } from '@backstage/plugin-search-react';

// Your search result item extension
import { YourSearchResultListItem } from '@backstage/your-plugin';

// Extensions provided by other plugin developers
import { ToolSearchResultListItem } from '@backstage/plugin-explore';
import { TechDocsSearchResultListItem } from '@backstage/plugin-techdocs';
import { CatalogSearchResultListItem } from '@internal/plugin-catalog-customized';

// This example omits other components, like filter and pagination
const SearchPage = () => (
  <Page themeId="home">
    <Header title="Search" />
    <Content>
      <Grid container direction="row">
        <Grid item xs={12}>
          <Paper>
            <SearchBar />
          </Paper>
        </Grid>
        <Grid item xs={12}>
          <SearchResult>
            <YourSearchResultListItem />
            <CatalogSearchResultListItem icon={<CatalogIcon />} />
            <TechDocsSearchResultListItem icon={<DocsIcon />} />
            <ToolSearchResultListItem icon={<BuildIcon />} />
          </SearchResult>
        </Grid>
      </Grid>
    </Content>
  </Page>
);

export const searchPage = <SearchPage />;
```

> **Important**: A default result item extension should be placed as the last child, so it can be used only when no other extensions match the result being rendered. If a non-default extension is specified, the `DefaultResultListItem` component will be used.

As another example, here's a search modal that renders results with extensions:

```tsx title="packages/app/src/components/searchModal.tsx"
import React from 'react';

import { DialogContent, DialogTitle, Paper } from '@material-ui/core';
import BuildIcon from '@material-ui/icons/Build';

import { DocsIcon, CatalogIcon } from '@backstage/core-components';
import { SearchBar, SearchResult } from '@backstage/plugin-search-react';

// Your search result item extension
import { YourSearchResultListItem } from '@backstage/your-plugin';

// Extensions provided by other plugin developers
import { ToolSearchResultListItem } from '@backstage/plugin-explore';
import { TechDocsSearchResultListItem } from '@backstage/plugin-techdocs';
import { CatalogSearchResultListItem } from '@internal/plugin-catalog-customized';

export const SearchModal = ({ toggleModal }: { toggleModal: () => void }) => (
  <>
    <DialogTitle>
      <Paper>
        <SearchBar />
      </Paper>
    </DialogTitle>
    <DialogContent>
      <SearchResult onClick={toggleModal}>
        <CatalogSearchResultListItem icon={<CatalogIcon />} />
        <TechDocsSearchResultListItem icon={<DocsIcon />} />
        <ToolSearchResultListItem icon={<BuildIcon />} />
        {/* As a "default" extension, it does not define a predicate function,
        so it must be the last child to render results that do not match the above extensions */}
        <YourSearchResultListItem />
      </SearchResult>
    </DialogContent>
  </>
);
```

There are other more specific search results layout components that also accept result item extensions, check their documentation: [SearchResultList](https://backstage.io/storybook/?path=/story/plugins-search-searchresultlist--with-result-item-extensions) and [SearchResultGroup](https://backstage.io/storybook/?path=/story/plugins-search-searchresultgroup--with-result-item-extensions).

## How to migrate your backend installation to use Search together with the new backend system

> DISCLAIMER: The new backend system is in alpha, and so are the search backend support for the new backend system. We don't recommend you to migrate your backend installations to the new system yet. But if you want to experiment, this is the guide for you!

Recently, the Backstage maintainers [announced the new Backend System](https://backstage.io/blog/2023/02/15/backend-system-alpha). The search plugins are now migrated to support the new backend system. In this guide you will learn how to update your backend set up.

In "packages/backend-next/index.ts", install the search plugin [1], the search engine [2], and the search collators/decorators modules [3]:

```ts
import { searchPlugin } from '@backstage/plugin-search-backend/alpha';
import { searchModuleElasticsearchEngine } from '@backstage/plugin-search-backend-module-elasticsearch/alpha';
import { searchModuleCatalogCollator } from '@backstage/plugin-search-backend-module-catalog/alpha';
import { searchModuleTechDocsCollator } from '@backstage/plugin-search-backend-module-techdocs/alpha';
import { searchModuleExploreCollator } from '@backstage/plugin-search-backend-module-explore/alpha';

const backend = createBackend();
// [1] adding the search plugin to the backend
backend.add(searchPlugin());
// [2] (optional) the default search engine is Lunr, if you want to extend the search backend with another search engine.
backend.add(searchModuleElasticsearchEngine());
// [3] extending search with collator modules to start index documents, take in optional schedule parameters.
backend.add(searchModuleCatalogCollator());
backend.add(searchModuleTechDocsCollator());
backend.add(searchModuleExploreCollator());

backend.start();
```

To create your own collators/decorators modules, please use the [searchModuleCatalogCollator](https://github.com/backstage/backstage/blob/d7f955f300893f50c4882ea8f5c09aa42dfaacfd/plugins/search-backend-module-catalog/src/alpha.ts#L49) as an example, we recommend that modules are separated by plugin packages (e.g. `search-backend-module-<plugin-id>`). You can also find the available search engines and collator/decorator modules documentation in the Alpha API reports:

**Search engine modules**

- Postgres [module](https://github.com/backstage/backstage/blob/d7f955f300893f50c4882ea8f5c09aa42dfaacfd/plugins/search-backend-module-pg/alpha-api-report.md);
- Elasticsearch [module](https://github.com/backstage/backstage/blob/d7f955f300893f50c4882ea8f5c09aa42dfaacfd/plugins/search-backend-module-elasticsearch/alpha-api-report.md).

**Search collator/decorator modules**

- Catalog [module](https://github.com/backstage/backstage/blob/d7f955f300893f50c4882ea8f5c09aa42dfaacfd/plugins/search-backend-module-catalog/alpha-api-report.md);
- Explore [module](https://github.com/backstage/backstage/blob/d7f955f300893f50c4882ea8f5c09aa42dfaacfd/plugins/search-backend-module-explore/alpha-api-report.md);
- TechDocs [module](https://github.com/backstage/backstage/blob/d7f955f300893f50c4882ea8f5c09aa42dfaacfd/plugins/search-backend-module-techdocs/alpha-api-report.md).

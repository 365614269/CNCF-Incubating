/*
 * Copyright 2020 The Backstage Authors
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
  Content,
  ContentHeader,
  CreateButton,
  Header,
  Page,
  SupportButton,
} from '@backstage/core-components';
import { TemplateEntityV1beta3 } from '@backstage/plugin-scaffolder-common';
import { useRouteRef } from '@backstage/core-plugin-api';
import {
  CatalogFilterLayout,
  EntityKindPicker,
  EntityListProvider,
  EntitySearchBar,
  EntityTagPicker,
  UserListPicker,
} from '@backstage/plugin-catalog-react';
import React, { ComponentType } from 'react';
import { TemplateList } from '../TemplateList';
import { TemplateTypePicker } from '../TemplateTypePicker';
import { catalogEntityCreatePermission } from '@backstage/plugin-catalog-common/alpha';
import { usePermission } from '@backstage/plugin-permission-react';
import { ScaffolderPageContextMenu } from './ScaffolderPageContextMenu';
import { registerComponentRouteRef } from '../../routes';

export type ScaffolderPageProps = {
  TemplateCardComponent?:
    | ComponentType<{ template: TemplateEntityV1beta3 }>
    | undefined;
  groups?: Array<{
    title?: React.ReactNode;
    filter: (entity: TemplateEntityV1beta3) => boolean;
  }>;
  templateFilter?: (entity: TemplateEntityV1beta3) => boolean;
  contextMenu?: {
    editor?: boolean;
    actions?: boolean;
    tasks?: boolean;
  };
  headerOptions?: {
    pageTitleOverride?: string;
    title?: string;
    subtitle?: string;
  };
};

export const ScaffolderPageContents = ({
  TemplateCardComponent,
  groups,
  templateFilter,
  contextMenu,
  headerOptions,
}: ScaffolderPageProps) => {
  const registerComponentLink = useRouteRef(registerComponentRouteRef);
  const otherTemplatesGroup = {
    title: groups ? 'Other Templates' : 'Templates',
    filter: (entity: TemplateEntityV1beta3) => {
      const filtered = (groups ?? []).map(group => group.filter(entity));
      return !filtered.some(result => result === true);
    },
  };

  const { allowed } = usePermission({
    permission: catalogEntityCreatePermission,
  });

  return (
    <Page themeId="home">
      <Header
        pageTitleOverride="Create a New Component"
        title="Create a New Component"
        subtitle="Create new software components using standard templates"
        {...headerOptions}
      >
        <ScaffolderPageContextMenu {...contextMenu} />
      </Header>
      <Content>
        <ContentHeader title="Available Templates">
          {allowed && (
            <CreateButton
              title="Register Existing Component"
              to={registerComponentLink && registerComponentLink()}
            />
          )}
          <SupportButton>
            Create new software components using standard templates. Different
            templates create different kinds of components (services, websites,
            documentation, ...).
          </SupportButton>
        </ContentHeader>

        <CatalogFilterLayout>
          <CatalogFilterLayout.Filters>
            <EntitySearchBar />
            <EntityKindPicker initialFilter="template" hidden />
            <UserListPicker
              initialFilter="all"
              availableFilters={['all', 'starred']}
            />
            <TemplateTypePicker />
            <EntityTagPicker />
          </CatalogFilterLayout.Filters>
          <CatalogFilterLayout.Content>
            {groups &&
              groups.map((group, index) => (
                <TemplateList
                  key={index}
                  TemplateCardComponent={TemplateCardComponent}
                  group={group}
                  templateFilter={templateFilter}
                />
              ))}
            <TemplateList
              key="other"
              TemplateCardComponent={TemplateCardComponent}
              templateFilter={templateFilter}
              group={otherTemplatesGroup}
            />
          </CatalogFilterLayout.Content>
        </CatalogFilterLayout>
      </Content>
    </Page>
  );
};

export const ScaffolderPage = ({
  TemplateCardComponent,
  groups,
  templateFilter,
  contextMenu,
  headerOptions,
}: ScaffolderPageProps) => (
  <EntityListProvider>
    <ScaffolderPageContents
      TemplateCardComponent={TemplateCardComponent}
      groups={groups}
      templateFilter={templateFilter}
      contextMenu={contextMenu}
      headerOptions={headerOptions}
    />
  </EntityListProvider>
);

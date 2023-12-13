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

import {
  catalogApiRef,
  useStarredEntities,
} from '@backstage/plugin-catalog-react';
import { Entity, stringifyEntityRef } from '@backstage/catalog-model';
import { useApi } from '@backstage/core-plugin-api';
import { Progress, ResponseErrorPanel } from '@backstage/core-components';
import { List, Typography, Tabs, Tab } from '@material-ui/core';
import React from 'react';
import useAsync from 'react-use/lib/useAsync';
import { StarredEntityListItem } from '../../components/StarredEntityListItem/StarredEntityListItem';

/**
 * A component to display a list of starred entities for the user.
 *
 * @public
 */

export type StarredEntitiesProps = {
  noStarredEntitiesMessage?: React.ReactNode | undefined;
  groupByKind?: boolean;
};

export const Content = ({
  noStarredEntitiesMessage,
  groupByKind,
}: StarredEntitiesProps) => {
  const catalogApi = useApi(catalogApiRef);
  const { starredEntities, toggleStarredEntity } = useStarredEntities();
  const [activeTab, setActiveTab] = React.useState(0);

  // Grab starred entities from catalog to ensure they still exist and also retrieve display titles
  const entities = useAsync(async () => {
    if (!starredEntities.size) {
      return [];
    }

    return (
      await catalogApi.getEntitiesByRefs({
        entityRefs: [...starredEntities],
        fields: [
          'kind',
          'metadata.namespace',
          'metadata.name',
          'metadata.title',
        ],
      })
    ).items.filter((e): e is Entity => !!e);
  }, [catalogApi, starredEntities]);

  if (starredEntities.size === 0)
    return (
      <Typography variant="body1">
        {noStarredEntitiesMessage ||
          'Click the star beside an entity name to add it to this list!'}
      </Typography>
    );

  if (entities.loading) {
    return <Progress />;
  }

  const groupedEntities: { [kind: string]: Entity[] } = {};
  entities.value?.forEach(entity => {
    const kind = entity.kind;
    if (!groupedEntities[kind]) {
      groupedEntities[kind] = [];
    }
    groupedEntities[kind].push(entity);
  });

  const groupByKindEntries = Object.entries(groupedEntities);

  return entities.error ? (
    <ResponseErrorPanel error={entities.error} />
  ) : (
    <div>
      {!groupByKind && (
        <List>
          {entities.value
            ?.sort((a, b) =>
              (a.metadata.title ?? a.metadata.name).localeCompare(
                b.metadata.title ?? b.metadata.name,
              ),
            )
            .map(entity => (
              <StarredEntityListItem
                key={stringifyEntityRef(entity)}
                entity={entity}
                onToggleStarredEntity={toggleStarredEntity}
              />
            ))}
        </List>
      )}

      {groupByKind && (
        <Tabs
          value={activeTab}
          onChange={(_, newValue) => setActiveTab(newValue)}
          variant="scrollable"
          scrollButtons="auto"
          aria-label="entity-tabs"
        >
          {groupByKindEntries.map(([kind]) => (
            <Tab key={kind} label={kind} />
          ))}
        </Tabs>
      )}

      {groupByKind &&
        groupByKindEntries.map(([kind, entitiesByKind], index) => (
          <div key={kind} hidden={groupByKind && activeTab !== index}>
            <List>
              {entitiesByKind
                ?.sort((a, b) =>
                  (a.metadata.title ?? a.metadata.name).localeCompare(
                    b.metadata.title ?? b.metadata.name,
                  ),
                )
                .map(entity => (
                  <StarredEntityListItem
                    key={stringifyEntityRef(entity)}
                    entity={entity}
                    onToggleStarredEntity={toggleStarredEntity}
                  />
                ))}
            </List>
          </div>
        ))}
    </div>
  );
};

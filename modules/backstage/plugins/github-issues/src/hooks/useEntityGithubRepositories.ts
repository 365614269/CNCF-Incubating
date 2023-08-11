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

import { Entity, stringifyEntityRef } from '@backstage/catalog-model';
import { useApi } from '@backstage/core-plugin-api';
import { catalogApiRef, useEntity } from '@backstage/plugin-catalog-react';
import { useCallback, useEffect, useState } from 'react';

const GITHUB_PROJECT_SLUG_ANNOTATION = 'github.com/project-slug';

export const getProjectNameFromEntity = (entity: Entity): string => {
  return entity?.metadata.annotations?.[GITHUB_PROJECT_SLUG_ANNOTATION] ?? '';
};

export function useEntityGithubRepositories() {
  const { entity } = useEntity();

  const catalogApi = useApi(catalogApiRef);
  const [repositories, setRepositories] = useState<string[]>([]);

  const getRepositoriesNames = useCallback(async () => {
    if (entity.kind === 'Component' || entity.kind === 'API') {
      const entityName = getProjectNameFromEntity(entity);

      if (entityName) {
        setRepositories([entityName]);
      }

      return;
    }

    const entitiesList = await catalogApi.getEntities({
      filter: {
        kind: ['Component', 'API'],
        'relations.ownedBy': stringifyEntityRef(entity),
      },
    });

    const entitiesNames: string[] = entitiesList.items.map(componentEntity =>
      getProjectNameFromEntity(componentEntity),
    );

    setRepositories([...new Set(entitiesNames)].filter(name => name.length));
  }, [catalogApi, entity]);

  useEffect(() => {
    getRepositoriesNames();
  }, [getRepositoriesNames]);

  return {
    repositories,
  };
}

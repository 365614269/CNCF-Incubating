/*
 * Copyright 2021 The Backstage Authors
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

import { PassThrough } from 'stream';
import os from 'os';
import { getVoidLogger } from '@backstage/backend-common';
import { CatalogApi } from '@backstage/catalog-client';
import { Entity } from '@backstage/catalog-model';
import { createFetchCatalogEntityAction } from './fetch';
import { examples } from './fetch.examples';
import yaml from 'yaml';

describe('catalog:fetch examples', () => {
  const getEntityByRef = jest.fn();
  const getEntitiesByRefs = jest.fn();

  const catalogClient = {
    getEntityByRef: getEntityByRef,
    getEntitiesByRefs: getEntitiesByRefs,
  };

  const action = createFetchCatalogEntityAction({
    catalogClient: catalogClient as unknown as CatalogApi,
  });

  const mockContext = {
    workspacePath: os.tmpdir(),
    logger: getVoidLogger(),
    logStream: new PassThrough(),
    output: jest.fn(),
    createTemporaryDirectory: jest.fn(),
    secrets: { backstageToken: 'secret' },
  };
  beforeEach(() => {
    jest.resetAllMocks();
  });

  describe('fetch single entity', () => {
    it('should return entity from catalog', async () => {
      getEntityByRef.mockReturnValueOnce({
        metadata: {
          namespace: 'default',
          name: 'name',
        },
        kind: 'Component',
      } as Entity);

      await action.handler({
        ...mockContext,
        input: yaml.parse(examples[0].example).steps[0].input,
      });

      expect(getEntityByRef).toHaveBeenCalledWith('component:default/name', {
        token: 'secret',
      });
      expect(mockContext.output).toHaveBeenCalledWith('entity', {
        metadata: {
          namespace: 'default',
          name: 'name',
        },
        kind: 'Component',
      });
    });
  });
});

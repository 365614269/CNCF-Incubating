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

import { Knex } from 'knex';
import { TestDatabases } from '@backstage/backend-test-utils';
import fs from 'fs';

const migrationsDir = `${__dirname}/../../migrations`;
const migrationsFiles = fs.readdirSync(migrationsDir).sort();

async function migrateUpOnce(knex: Knex): Promise<void> {
  await knex.migrate.up({ directory: migrationsDir });
}

async function migrateDownOnce(knex: Knex): Promise<void> {
  await knex.migrate.down({ directory: migrationsDir });
}

async function migrateUntilBefore(knex: Knex, target: string): Promise<void> {
  const index = migrationsFiles.indexOf(target);
  if (index === -1) {
    throw new Error(`Migration ${target} not found`);
  }
  for (let i = 0; i < index; i++) {
    await migrateUpOnce(knex);
  }
}

jest.setTimeout(60_000);

describe('migrations', () => {
  const databases = TestDatabases.create({
    ids: ['MYSQL_8', 'POSTGRES_13', 'POSTGRES_9', 'SQLITE_3'],
  });

  it.each(databases.eachSupportedId())(
    'latest version correctly cascades deletions, %p',
    async databaseId => {
      const knex = await databases.init(databaseId);
      await knex.migrate.latest({ directory: migrationsDir });

      await knex
        .insert({
          entity_id: 'i1',
          entity_ref: 'k:ns/n1',
          unprocessed_entity: '{}',
          errors: '[]',
          next_update_at: new Date(),
          last_discovery_at: new Date(),
        })
        .into('refresh_state');
      await knex
        .insert({
          entity_id: 'i2',
          entity_ref: 'k:ns/n2',
          unprocessed_entity: '{}',
          errors: '[]',
          next_update_at: new Date(),
          last_discovery_at: new Date(),
        })
        .into('refresh_state');
      await knex
        .insert({ entity_id: 'i1', key: 'k1', value: 'v1' })
        .into('search');
      await knex
        .insert({
          source_entity_ref: 'k:ns/n1',
          target_entity_ref: 'k:ns/n2',
        })
        .into('refresh_state_references');
      await knex
        .insert({
          originating_entity_id: 'i1',
          source_entity_ref: 'k:ns/n1',
          target_entity_ref: 'k:ns/n2',
          type: 't',
        })
        .into('relations');
      await knex
        .insert({
          entity_id: 'i1',
          hash: 'h',
          stitch_ticket: '',
          final_entity: '{}',
        })
        .into('final_entities');

      await knex.delete().from('refresh_state').where({ entity_id: 'i1' });

      await expect(knex('search')).resolves.toEqual([]);
      await expect(knex('refresh_state_references')).resolves.toEqual([]);
      await expect(knex('relations')).resolves.toEqual([]);
      await expect(knex('final_entities')).resolves.toEqual([]);
    },
  );

  it.each(databases.eachSupportedId())(
    '20221109192547_search_add_original_value_column.js, %p',
    async databaseId => {
      const knex = await databases.init(databaseId);

      await migrateUntilBefore(
        knex,
        '20221109192547_search_add_original_value_column.js',
      );

      await knex
        .insert({
          entity_id: 'i',
          entity_ref: 'k:ns/n',
          unprocessed_entity: '{}',
          errors: '[]',
          next_update_at: new Date(),
          last_discovery_at: new Date(),
        })
        .into('refresh_state');
      await knex
        .insert({ entity_id: 'i', key: 'k1', value: 'v1' })
        .into('search');
      await knex
        .insert({ entity_id: 'i', key: 'k2', value: null })
        .into('search');

      await expect(knex('search')).resolves.toEqual(
        expect.arrayContaining([
          { entity_id: 'i', key: 'k1', value: 'v1' },
          { entity_id: 'i', key: 'k2', value: null },
        ]),
      );

      await migrateUpOnce(knex);

      await expect(knex('search')).resolves.toEqual(
        expect.arrayContaining([
          { entity_id: 'i', key: 'k1', value: 'v1', original_value: 'v1' },
          { entity_id: 'i', key: 'k2', value: null, original_value: null },
        ]),
      );

      await migrateDownOnce(knex);

      await expect(knex('search')).resolves.toEqual(
        expect.arrayContaining([
          { entity_id: 'i', key: 'k1', value: 'v1' },
          { entity_id: 'i', key: 'k2', value: null },
        ]),
      );

      await knex.destroy();
    },
  );

  it.each(databases.eachSupportedId())(
    '20221201085245_add_last_updated_at_in_final_entities.js, %p',
    async databaseId => {
      const knex = await databases.init(databaseId);

      await migrateUntilBefore(
        knex,
        '20221201085245_add_last_updated_at_in_final_entities.js',
      );

      await knex
        .insert([
          {
            entity_id: 'my-id',
            entity_ref: 'k:ns/n',
            unprocessed_entity: JSON.stringify({}),
            processed_entity: JSON.stringify({
              apiVersion: 'a',
              kind: 'k',
              metadata: {
                name: 'n',
                namespace: 'ns',
              },
              spec: {
                k: 'v',
              },
            }),
            errors: '[]',
            next_update_at: knex.fn.now(),
            last_discovery_at: knex.fn.now(),
          },
        ])
        .into('refresh_state');

      await knex
        .insert({
          entity_id: 'my-id',
          hash: 'd1c0c56d5fea4238e4c091d9dde4cb42d05a6b7e',
          stitch_ticket: '52367ed7-120b-405f-b7e0-cdd90f956312',
          final_entity:
            '{"apiVersion":"a","kind":"k","metadata":{"name":"n","namespace":"ns","uid":"my-id","etag":"d1c0c56d5fea4238e4c091d9dde4cb42d05a6b7e"},"spec":{"k":"v"},"relations":[{"type":"looksAt","targetRef":"k:ns/other"}]}',
        })
        .into('final_entities');

      await migrateUpOnce(knex);

      await expect(knex('final_entities')).resolves.toEqual(
        expect.arrayContaining([
          {
            entity_id: 'my-id',
            hash: 'd1c0c56d5fea4238e4c091d9dde4cb42d05a6b7e',
            stitch_ticket: '52367ed7-120b-405f-b7e0-cdd90f956312',
            final_entity:
              '{"apiVersion":"a","kind":"k","metadata":{"name":"n","namespace":"ns","uid":"my-id","etag":"d1c0c56d5fea4238e4c091d9dde4cb42d05a6b7e"},"spec":{"k":"v"},"relations":[{"type":"looksAt","targetRef":"k:ns/other"}]}',
            last_updated_at: null,
          },
        ]),
      );

      await migrateDownOnce(knex);

      await expect(knex('final_entities')).resolves.toEqual(
        expect.arrayContaining([
          {
            entity_id: 'my-id',
            hash: 'd1c0c56d5fea4238e4c091d9dde4cb42d05a6b7e',
            stitch_ticket: '52367ed7-120b-405f-b7e0-cdd90f956312',
            final_entity:
              '{"apiVersion":"a","kind":"k","metadata":{"name":"n","namespace":"ns","uid":"my-id","etag":"d1c0c56d5fea4238e4c091d9dde4cb42d05a6b7e"},"spec":{"k":"v"},"relations":[{"type":"looksAt","targetRef":"k:ns/other"}]}',
          },
        ]),
      );

      await knex.destroy();
    },
  );

  it.each(databases.eachSupportedId())(
    '20230525141717_stitch_queue.js, %p',
    async databaseId => {
      const knex = await databases.init(databaseId);

      await migrateUntilBefore(knex, '20230525141717_stitch_queue.js');

      await knex
        .insert([
          {
            entity_id: 'my-id',
            entity_ref: 'k:ns/n',
            unprocessed_entity: '{}',
            processed_entity: '{}',
            errors: '[]',
            next_update_at: knex.fn.now(),
            last_discovery_at: knex.fn.now(),
          },
        ])
        .into('refresh_state');
      await knex
        .insert({
          entity_id: 'my-id',
          hash: 'd1c0c56d5fea4238e4c091d9dde4cb42d05a6b7e',
          stitch_ticket: '',
          final_entity: '{}',
        })
        .into('final_entities');

      await migrateUpOnce(knex);

      await expect(knex('refresh_state')).resolves.toEqual([
        {
          entity_id: 'my-id',
          entity_ref: 'k:ns/n',
          location_key: null,
          unprocessed_entity: '{}',
          processed_entity: '{}',
          errors: '[]',
          cache: null,
          unprocessed_hash: null,
          result_hash: null,
          next_update_at: expect.anything(),
          next_stitch_at: null,
          next_stitch_ticket: null,
          last_discovery_at: expect.anything(),
        },
      ]);

      await migrateDownOnce(knex);

      await expect(knex('refresh_state')).resolves.toEqual([
        {
          entity_id: 'my-id',
          entity_ref: 'k:ns/n',
          location_key: null,
          unprocessed_entity: '{}',
          processed_entity: '{}',
          errors: '[]',
          cache: null,
          unprocessed_hash: null,
          result_hash: null,
          next_update_at: expect.anything(),
          last_discovery_at: expect.anything(),
        },
      ]);

      await knex.destroy();
    },
  );
});

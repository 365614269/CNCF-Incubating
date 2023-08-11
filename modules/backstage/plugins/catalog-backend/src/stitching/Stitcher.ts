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

import { ENTITY_STATUS_CATALOG_PROCESSING_TYPE } from '@backstage/catalog-client';
import { AlphaEntity, EntityStatusItem } from '@backstage/catalog-model/alpha';
import {
  ANNOTATION_EDIT_URL,
  ANNOTATION_VIEW_URL,
  EntityRelation,
} from '@backstage/catalog-model';
import { SerializedError, stringifyError } from '@backstage/errors';
import { Knex } from 'knex';
import { v4 as uuid } from 'uuid';
import { Logger } from 'winston';
import {
  DbFinalEntitiesRow,
  DbRefreshStateRow,
  DbSearchRow,
} from '../database/tables';
import { buildEntitySearch } from './buildEntitySearch';
import { BATCH_SIZE, generateStableHash } from './util';

// See https://github.com/facebook/react/blob/f0cf832e1d0c8544c36aa8b310960885a11a847c/packages/react-dom-bindings/src/shared/sanitizeURL.js
const scriptProtocolPattern =
  // eslint-disable-next-line no-control-regex
  /^[\u0000-\u001F ]*j[\r\n\t]*a[\r\n\t]*v[\r\n\t]*a[\r\n\t]*s[\r\n\t]*c[\r\n\t]*r[\r\n\t]*i[\r\n\t]*p[\r\n\t]*t[\r\n\t]*\:/i;

/**
 * Performs the act of stitching - to take all of the various outputs from the
 * ingestion process, and stitching them together into the final entity JSON
 * shape.
 */
export class Stitcher {
  constructor(
    private readonly database: Knex,
    private readonly logger: Logger,
  ) {}

  async stitch(entityRefs: Set<string>) {
    for (const entityRef of entityRefs) {
      try {
        await this.stitchOne(entityRef);
      } catch (error) {
        this.logger.error(
          `Failed to stitch ${entityRef}, ${stringifyError(error)}`,
        );
      }
    }
  }

  private async stitchOne(entityRef: string): Promise<void> {
    const entityResult = await this.database<DbRefreshStateRow>('refresh_state')
      .where({ entity_ref: entityRef })
      .limit(1)
      .select('entity_id');
    if (!entityResult.length) {
      // Entity does no exist in refresh state table, no stitching required.
      return;
    }

    // Insert stitching ticket that will be compared before inserting the final entity.
    const ticket = uuid();
    await this.database<DbFinalEntitiesRow>('final_entities')
      .insert({
        entity_id: entityResult[0].entity_id,
        hash: '',
        stitch_ticket: ticket,
      })
      .onConflict('entity_id')
      .merge(['stitch_ticket']);

    // Selecting from refresh_state and final_entities should yield exactly
    // one row (except in abnormal cases where the stitch was invoked for
    // something that didn't exist at all, in which case it's zero rows).
    // The join with the temporary incoming_references still gives one row.
    const [processedResult, relationsResult] = await Promise.all([
      this.database
        .with('incoming_references', function incomingReferences(builder) {
          return builder
            .from('refresh_state_references')
            .where({ target_entity_ref: entityRef })
            .count({ count: '*' });
        })
        .select({
          entityId: 'refresh_state.entity_id',
          processedEntity: 'refresh_state.processed_entity',
          errors: 'refresh_state.errors',
          incomingReferenceCount: 'incoming_references.count',
          previousHash: 'final_entities.hash',
        })
        .from('refresh_state')
        .where({ 'refresh_state.entity_ref': entityRef })
        .crossJoin(this.database.raw('incoming_references'))
        .leftOuterJoin('final_entities', {
          'final_entities.entity_id': 'refresh_state.entity_id',
        }),
      this.database
        .distinct({
          relationType: 'type',
          relationTarget: 'target_entity_ref',
        })
        .from('relations')
        .where({ source_entity_ref: entityRef })
        .orderBy('relationType', 'asc')
        .orderBy('relationTarget', 'asc'),
    ]);

    // If there were no rows returned, it would mean that there was no
    // matching row even in the refresh_state. This can happen for example
    // if we emit a relation to something that hasn't been ingested yet.
    // It's safe to ignore this stitch attempt in that case.
    if (!processedResult.length) {
      this.logger.error(
        `Unable to stitch ${entityRef}, item does not exist in refresh state table`,
      );
      return;
    }

    const {
      entityId,
      processedEntity,
      errors,
      incomingReferenceCount,
      previousHash,
    } = processedResult[0];

    // If there was no processed entity in place, the target hasn't been
    // through the processing steps yet. It's safe to ignore this stitch
    // attempt in that case, since another stitch will be triggered when
    // that processing has finished.
    if (!processedEntity) {
      this.logger.debug(
        `Unable to stitch ${entityRef}, the entity has not yet been processed`,
      );
      return;
    }

    // Grab the processed entity and stitch all of the relevant data into
    // it
    const entity = JSON.parse(processedEntity) as AlphaEntity;
    const isOrphan = Number(incomingReferenceCount) === 0;
    let statusItems: EntityStatusItem[] = [];

    if (isOrphan) {
      this.logger.debug(`${entityRef} is an orphan`);
      entity.metadata.annotations = {
        ...entity.metadata.annotations,
        ['backstage.io/orphan']: 'true',
      };
    }
    if (errors) {
      const parsedErrors = JSON.parse(errors) as SerializedError[];
      if (Array.isArray(parsedErrors) && parsedErrors.length) {
        statusItems = parsedErrors.map(e => ({
          type: ENTITY_STATUS_CATALOG_PROCESSING_TYPE,
          level: 'error',
          message: `${e.name}: ${e.message}`,
          error: e,
        }));
      }
    }
    // We opt to do this check here as we otherwise can't guarantee that it will be run after all processors
    for (const annotation of [ANNOTATION_VIEW_URL, ANNOTATION_EDIT_URL]) {
      const value = entity.metadata.annotations?.[annotation];
      if (typeof value === 'string' && scriptProtocolPattern.test(value)) {
        entity.metadata.annotations![annotation] =
          'https://backstage.io/annotation-rejected-for-security-reasons';
      }
    }

    // TODO: entityRef is lower case and should be uppercase in the final
    // result
    entity.relations = relationsResult
      .filter(row => row.relationType /* exclude null row, if relevant */)
      .map<EntityRelation>(row => ({
        type: row.relationType!,
        targetRef: row.relationTarget!,
      }));
    if (statusItems.length) {
      entity.status = {
        ...entity.status,
        items: [...(entity.status?.items ?? []), ...statusItems],
      };
    }

    // If the output entity was actually not changed, just abort
    const hash = generateStableHash(entity);
    if (hash === previousHash) {
      this.logger.debug(`Skipped stitching of ${entityRef}, no changes`);
      return;
    }

    entity.metadata.uid = entityId;
    if (!entity.metadata.etag) {
      // If the original data source did not have its own etag handling,
      // use the hash as a good-quality etag
      entity.metadata.etag = hash;
    }

    // This may throw if the entity is invalid, so we call it before
    // the final_entities write, even though we may end up not needing
    // to write the search index.
    const searchEntries = buildEntitySearch(entityId, entity);

    const amountOfRowsChanged = await this.database<DbFinalEntitiesRow>(
      'final_entities',
    )
      .update({
        final_entity: JSON.stringify(entity),
        hash,
        last_updated_at: this.database.fn.now(),
      })
      .where('entity_id', entityId)
      .where('stitch_ticket', ticket)
      .onConflict('entity_id')
      .merge(['final_entity', 'hash', 'last_updated_at']);

    if (amountOfRowsChanged === 0) {
      this.logger.debug(
        `Entity ${entityRef} is already processed, skipping write.`,
      );
      return;
    }

    // TODO(freben): Search will probably need a similar safeguard against
    // race conditions like the final_entities ticket handling above.
    // Otherwise, it can be the case that:
    // A writes the entity ->
    // B writes the entity ->
    // B writes search ->
    // A writes search
    await this.database<DbSearchRow>('search')
      .where({ entity_id: entityId })
      .delete();
    await this.database.batchInsert('search', searchEntries, BATCH_SIZE);
  }
}

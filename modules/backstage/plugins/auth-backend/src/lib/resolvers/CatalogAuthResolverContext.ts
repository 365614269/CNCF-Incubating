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

import { TokenManager } from '@backstage/backend-common';
import { CatalogApi } from '@backstage/catalog-client';
import {
  DEFAULT_NAMESPACE,
  Entity,
  parseEntityRef,
  RELATION_MEMBER_OF,
  stringifyEntityRef,
} from '@backstage/catalog-model';
import { ConflictError, InputError, NotFoundError } from '@backstage/errors';
import {
  AuthService,
  DiscoveryService,
  HttpAuthService,
  LoggerService,
} from '@backstage/backend-plugin-api';
import { TokenIssuer } from '../../identity/types';
import { CatalogIdentityClient } from '../catalog';
import {
  AuthResolverCatalogUserQuery,
  AuthResolverContext,
  TokenParams,
} from '@backstage/plugin-auth-node';

/**
 * Uses the default ownership resolution logic to return an array
 * of entity refs that the provided entity claims ownership through.
 *
 * A reference to the entity itself will also be included in the returned array.
 *
 * @public
 */
export function getDefaultOwnershipEntityRefs(entity: Entity) {
  const membershipRefs =
    entity.relations
      ?.filter(
        r => r.type === RELATION_MEMBER_OF && r.targetRef.startsWith('group:'),
      )
      .map(r => r.targetRef) ?? [];

  return Array.from(new Set([stringifyEntityRef(entity), ...membershipRefs]));
}

/**
 * @internal
 */
export class CatalogAuthResolverContext implements AuthResolverContext {
  static create(options: {
    logger: LoggerService;
    catalogApi: CatalogApi;
    tokenIssuer: TokenIssuer;
    tokenManager: TokenManager;
    discovery: DiscoveryService;
    auth: AuthService;
    httpAuth: HttpAuthService;
  }): CatalogAuthResolverContext {
    const catalogIdentityClient = new CatalogIdentityClient({
      catalogApi: options.catalogApi,
      tokenManager: options.tokenManager,
      discovery: options.discovery,
      auth: options.auth,
      httpAuth: options.httpAuth,
    });

    return new CatalogAuthResolverContext(
      options.logger,
      options.tokenIssuer,
      catalogIdentityClient,
      options.catalogApi,
      options.auth,
    );
  }

  private constructor(
    public readonly logger: LoggerService,
    public readonly tokenIssuer: TokenIssuer,
    public readonly catalogIdentityClient: CatalogIdentityClient,
    private readonly catalogApi: CatalogApi,
    private readonly auth: AuthService,
  ) {}

  async issueToken(params: TokenParams) {
    const token = await this.tokenIssuer.issueToken(params);
    return { token };
  }

  async findCatalogUser(query: AuthResolverCatalogUserQuery) {
    let result: Entity[] | Entity | undefined = undefined;
    const { token } = await this.auth.getPluginRequestToken({
      onBehalfOf: await this.auth.getOwnServiceCredentials(),
      targetPluginId: 'catalog',
    });

    if ('entityRef' in query) {
      const entityRef = parseEntityRef(query.entityRef, {
        defaultKind: 'User',
        defaultNamespace: DEFAULT_NAMESPACE,
      });
      result = await this.catalogApi.getEntityByRef(entityRef, { token });
    } else if ('annotations' in query) {
      const filter: Record<string, string> = {
        kind: 'user',
      };
      for (const [key, value] of Object.entries(query.annotations)) {
        filter[`metadata.annotations.${key}`] = value;
      }
      const res = await this.catalogApi.getEntities({ filter }, { token });
      result = res.items;
    } else if ('filter' in query) {
      const res = await this.catalogApi.getEntities(
        { filter: query.filter },
        { token },
      );
      result = res.items;
    } else {
      throw new InputError('Invalid user lookup query');
    }

    if (Array.isArray(result)) {
      if (result.length > 1) {
        throw new ConflictError('User lookup resulted in multiple matches');
      }
      result = result[0];
    }
    if (!result) {
      throw new NotFoundError('User not found');
    }

    return { entity: result };
  }

  async signInWithCatalogUser(query: AuthResolverCatalogUserQuery) {
    const { entity } = await this.findCatalogUser(query);
    const ownershipRefs = getDefaultOwnershipEntityRefs(entity);

    const token = await this.tokenIssuer.issueToken({
      claims: {
        sub: stringifyEntityRef(entity),
        ent: ownershipRefs,
      },
    });
    return { token };
  }
}

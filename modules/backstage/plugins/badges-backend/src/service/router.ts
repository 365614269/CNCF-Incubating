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

import express from 'express';
import Router from 'express-promise-router';
import {
  DatabaseManager,
  errorHandler,
  PluginEndpointDiscovery,
  TokenManager,
} from '@backstage/backend-common';
import { CatalogApi, CatalogClient } from '@backstage/catalog-client';
import { Config } from '@backstage/config';
import { AuthenticationError, NotFoundError } from '@backstage/errors';
import { BadgeBuilder, DefaultBadgeBuilder } from '../lib/BadgeBuilder';
import { BadgeContext, BadgeFactories } from '../types';
import { isNil } from 'lodash';
import { Logger } from 'winston';
import { IdentityApi } from '@backstage/plugin-auth-node';
import { getBearerTokenFromAuthorizationHeader } from '@backstage/plugin-auth-node';
import { BadgesStore, DatabaseBadgesStore } from '../database/badgesStore';
import { createDefaultBadgeFactories } from '../badges';

/** @public */
export interface RouterOptions {
  badgeBuilder?: BadgeBuilder;
  badgeFactories?: BadgeFactories;
  catalog?: CatalogApi;
  config: Config;
  discovery: PluginEndpointDiscovery;
  tokenManager: TokenManager;
  logger: Logger;
  identity: IdentityApi;
  badgeStore?: BadgesStore;
}

/** @public */
export async function createRouter(
  options: RouterOptions,
): Promise<express.Router> {
  const catalog =
    options.catalog || new CatalogClient({ discoveryApi: options.discovery });
  const badgeBuilder =
    options.badgeBuilder ||
    new DefaultBadgeBuilder(
      options.badgeFactories || createDefaultBadgeFactories(),
    );
  const router = Router();

  const { config, logger, tokenManager, discovery, identity } = options;
  const baseUrl = await discovery.getExternalBaseUrl('badges');

  if (config.getOptionalBoolean('app.badges.obfuscate')) {
    return obfuscatedRoute(
      router,
      catalog,
      badgeBuilder,
      tokenManager,
      logger,
      options,
      config,
      identity,
      baseUrl,
    );
  }
  return nonObfuscatedRoute(
    router,
    catalog,
    badgeBuilder,
    tokenManager,
    config,
    baseUrl,
  );
}

async function obfuscatedRoute(
  router: express.Router,
  catalog: CatalogApi,
  badgeBuilder: BadgeBuilder,
  tokenManager: TokenManager,
  logger: Logger,
  options: RouterOptions,
  config: Config,
  identity: IdentityApi,
  baseUrl: string,
) {
  logger.info('Badges obfuscation is enabled');

  const store = options.badgeStore
    ? options.badgeStore
    : await DatabaseBadgesStore.create({
        database: await DatabaseManager.fromConfig(config).forPlugin('badges'),
      });

  router.get('/entity/:entityUuid/badge-specs', async (req, res) => {
    const { entityUuid } = req.params;

    // Retrieve the badge info from the database
    const badgeInfos = await store.getBadgeFromUuid(entityUuid);

    if (isNil(badgeInfos)) {
      throw new NotFoundError(`No badge found for entity uuid "${entityUuid}"`);
    }

    // If a mapping is found, map name, namespace and kind
    const name = badgeInfos.name;
    const namespace = badgeInfos.namespace;
    const kind = badgeInfos.kind;
    const token = await tokenManager.getToken();

    // Query the catalog with the name, namespace, kind to get the entity informations
    const entity = await catalog.getEntityByRef(
      {
        namespace,
        kind,
        name,
      },
      token,
    );
    if (isNil(entity)) {
      throw new NotFoundError(
        `No ${kind} entity in ${namespace} named "${name}"`,
      );
    }

    // Create the badge specs
    const specs = [];
    for (const badgeInfo of await badgeBuilder.getBadges()) {
      const context: BadgeContext = {
        badgeUrl: `${baseUrl}/entity/${entityUuid}/${badgeInfo.id}`,
        config: config,
        entity,
      };

      const badge = await badgeBuilder.createBadgeJson({
        badgeInfo,
        context,
      });
      specs.push(badge);
    }

    res.status(200).json(specs);
  });

  router.get('/entity/:entityUuid/:badgeId', async (req, res) => {
    const { entityUuid, badgeId } = req.params;

    // Retrieve the badge info from the database
    const badgeInfo = await store.getBadgeFromUuid(entityUuid);

    if (isNil(badgeInfo)) {
      throw new NotFoundError(`No badge found for entity uuid "${entityUuid}"`);
    }

    // If a mapping is found, map name, namespace and kind
    const name = badgeInfo.name;
    const namespace = badgeInfo.namespace;
    const kind = badgeInfo.kind;
    const token = await tokenManager.getToken();
    const entity = await catalog.getEntityByRef(
      {
        namespace,
        kind,
        name,
      },
      token,
    );
    if (isNil(entity)) {
      throw new NotFoundError(
        `No ${kind} entity in ${namespace} named "${name}"`,
        res.sendStatus(404),
      );
    }

    let format =
      req.accepts(['image/svg+xml', 'application/json']) || 'image/svg+xml';
    if (req.query.format === 'json') {
      format = 'application/json';
    }

    const badgeOptions = {
      badgeInfo: { id: badgeId },
      context: {
        badgeUrl: `${baseUrl}/entity/${entityUuid}/${badgeId}`,
        config: config,
        entity,
      },
    };

    let data: string;
    if (format === 'application/json') {
      data = JSON.stringify(
        await badgeBuilder.createBadgeJson(badgeOptions),
        null,
        2,
      );
    } else {
      data = await badgeBuilder.createBadgeSvg(badgeOptions);
    }

    res.setHeader('Content-Type', format);
    res.status(200).send(data);
  });

  router.get(
    '/entity/:namespace/:kind/:name/obfuscated',
    function authenticate(req, _res, next) {
      const token =
        getBearerTokenFromAuthorizationHeader(req.headers.authorization) ||
        (req.cookies?.token as string | undefined);

      if (!token) {
        throw new AuthenticationError('Unauthorized');
      }

      try {
        req.user = identity.getIdentity({ request: req });
        next();
      } catch (error) {
        tokenManager.authenticate(token.toString());
        next(error);
      }
    },
    async (req, res) => {
      const { namespace, kind, name } = req.params;
      const storedEntityUuid: { uuid: string } | undefined =
        await store.getBadgeUuid(name, namespace, kind);

      if (isNil(storedEntityUuid)) {
        throw new NotFoundError(
          `No uuid found for entity "${namespace}/${kind}/${name}"`,
        );
      }

      return res.status(200).json(storedEntityUuid);
    },
  );

  router.use(errorHandler());

  return router;
}

async function nonObfuscatedRoute(
  router: express.Router,
  catalog: CatalogApi,
  badgeBuilder: BadgeBuilder,
  tokenManager: TokenManager,
  config: Config,
  baseUrl: string,
) {
  router.get('/entity/:namespace/:kind/:name/badge-specs', async (req, res) => {
    const token = await tokenManager.getToken();
    const { namespace, kind, name } = req.params;
    const entity = await catalog.getEntityByRef(
      { namespace, kind, name },
      token,
    );
    if (!entity) {
      throw new NotFoundError(
        `No ${kind} entity in ${namespace} named "${name}"`,
      );
    }

    const specs = [];
    for (const badgeInfo of await badgeBuilder.getBadges()) {
      const badgeId = badgeInfo.id;
      const context: BadgeContext = {
        badgeUrl: `${baseUrl}/entity/${namespace}/${kind}/${name}/badge/${badgeId}`,
        config: config,
        entity,
      };

      const badge = await badgeBuilder.createBadgeJson({
        badgeInfo,
        context,
      });
      specs.push(badge);
    }

    res.status(200).json(specs);
  });

  router.get(
    '/entity/:namespace/:kind/:name/badge/:badgeId',
    async (req, res) => {
      const { namespace, kind, name, badgeId } = req.params;
      const token = await tokenManager.getToken();
      const entity = await catalog.getEntityByRef(
        { namespace, kind, name },
        token,
      );
      if (!entity) {
        throw new NotFoundError(
          `No ${kind} entity in ${namespace} named "${name}"`,
        );
      }

      let format =
        req.accepts(['image/svg+xml', 'application/json']) || 'image/svg+xml';
      if (req.query.format === 'json') {
        format = 'application/json';
      }

      const badgeOptions = {
        badgeInfo: { id: badgeId },
        context: {
          badgeUrl: `${baseUrl}/entity/${namespace}/${kind}/${name}/badge/${badgeId}`,
          config: config,
          entity,
        },
      };

      let data: string;
      if (format === 'application/json') {
        data = JSON.stringify(
          await badgeBuilder.createBadgeJson(badgeOptions),
          null,
          2,
        );
      } else {
        data = await badgeBuilder.createBadgeSvg(badgeOptions);
      }

      res.setHeader('Content-Type', format);
      res.status(200).send(data);
    },
  );

  router.use(errorHandler());

  return router;
}

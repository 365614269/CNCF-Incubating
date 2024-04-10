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
  notFoundHandler,
  PluginDatabaseManager,
  resolvePackagePath,
} from '@backstage/backend-common';
import { AppConfig, Config } from '@backstage/config';
import helmet from 'helmet';
import express from 'express';
import Router from 'express-promise-router';
import fs from 'fs-extra';
import { resolve as resolvePath } from 'path';
import { Logger } from 'winston';
import { injectConfig, readConfigs } from '../lib/config';
import {
  StaticAssetsStore,
  findStaticAssets,
  createStaticAssetMiddleware,
} from '../lib/assets';
import {
  CACHE_CONTROL_MAX_CACHE,
  CACHE_CONTROL_NO_CACHE,
  CACHE_CONTROL_REVALIDATE_CACHE,
} from '../lib/headers';
import { ConfigSchema } from '@backstage/config-loader';
import { AuthService, HttpAuthService } from '@backstage/backend-plugin-api';
import { AuthenticationError } from '@backstage/errors';

// express uses mime v1 while we only have types for mime v2
type Mime = { lookup(arg0: string): string };

/** @public */
export interface RouterOptions {
  config: Config;
  logger: Logger;
  auth?: AuthService;
  httpAuth?: HttpAuthService;

  /**
   * If a database is provided it will be used to cache previously deployed static assets.
   *
   * This is a built-in alternative to using a `staticFallbackHandler`.
   */
  database?: PluginDatabaseManager;

  /**
   * The name of the app package that content should be served from. The same app package should be
   * added as a dependency to the backend package in order for it to be accessible at runtime.
   *
   * In a typical setup with a single app package this would be set to 'app'.
   */
  appPackageName: string;

  /**
   * A request handler to handle requests for static content that are not present in the app bundle.
   *
   * This can be used to avoid issues with clients on older deployment versions trying to access lazy
   * loaded content that is no longer present. Typically the requests would fall back to a long-term
   * object store where all recently deployed versions of the app are present.
   *
   * Another option is to provide a `database` that will take care of storing the static assets instead.
   *
   * If both `database` and `staticFallbackHandler` are provided, the `database` will attempt to serve
   * static assets first, and if they are not found, the `staticFallbackHandler` will be called.
   */
  staticFallbackHandler?: express.Handler;

  /**
   * Disables the configuration injection. This can be useful if you're running in an environment
   * with a read-only filesystem, or for some other reason don't want configuration to be injected.
   *
   * Note that this will cause the configuration used when building the app bundle to be used, unless
   * a separate configuration loading strategy is set up.
   *
   * This also disables configuration injection though `APP_CONFIG_` environment variables.
   */
  disableConfigInjection?: boolean;

  /**
   *
   * Provides a ConfigSchema.
   *
   */
  schema?: ConfigSchema;
}

/** @public */
export async function createRouter(
  options: RouterOptions,
): Promise<express.Router> {
  const {
    config,
    logger,
    appPackageName,
    staticFallbackHandler,
    auth,
    httpAuth,
  } = options;

  const disableConfigInjection =
    options.disableConfigInjection ??
    config.getOptionalBoolean('app.disableConfigInjection');
  const disableStaticFallbackCache = config.getOptionalBoolean(
    'app.disableStaticFallbackCache',
  );

  const appDistDir = resolvePackagePath(appPackageName, 'dist');
  const staticDir = resolvePath(appDistDir, 'static');

  if (!(await fs.pathExists(staticDir))) {
    if (process.env.NODE_ENV === 'production') {
      logger.error(
        `Can't serve static app content from ${staticDir}, directory doesn't exist`,
      );
    }

    return Router();
  }

  logger.info(`Serving static app content from ${appDistDir}`);

  const appConfigs = disableConfigInjection
    ? undefined
    : await readConfigs({
        config,
        appDistDir,
        env: process.env,
      });

  const assetStore =
    options.database && !disableStaticFallbackCache
      ? await StaticAssetsStore.create({
          logger,
          database: options.database,
        })
      : undefined;

  const router = Router();

  router.use(helmet.frameguard({ action: 'deny' }));

  const publicDistDir = resolvePath(appDistDir, 'public');

  const enablePublicEntryPoint =
    (await fs.pathExists(publicDistDir)) && auth && httpAuth;

  if (enablePublicEntryPoint && auth && httpAuth) {
    logger.info(
      `App is running in protected mode, serving public content from ${publicDistDir}`,
    );

    const publicRouter = Router();

    publicRouter.use(async (req, res, next) => {
      try {
        const credentials = await httpAuth.credentials(req, {
          allow: ['user', 'service', 'none'],
          allowLimitedAccess: true,
        });

        if (credentials.principal.type === 'none') {
          next();
        } else {
          next('router');
        }
      } catch {
        // If we fail to authenticate, make sure the session cookie is cleared
        // and continue as unauthenticated. If the user is logged in they will
        // immediately be redirected back to the protected app via the POST.
        await httpAuth.issueUserCookie(res, {
          credentials: await auth.getNoneCredentials(),
        });
        next();
      }
    });

    publicRouter.post(
      '*',
      express.urlencoded({ extended: true }),
      async (req, res, next) => {
        if (req.body.type === 'sign-in') {
          const credentials = await auth.authenticate(req.body.token);

          if (!auth.isPrincipal(credentials, 'user')) {
            throw new AuthenticationError('Invalid token, not a user');
          }

          await httpAuth.issueUserCookie(res, {
            credentials,
          });

          // Resume as if it was a GET request towards the outer protected router, serving index.html
          req.method = 'GET';
          next('router');
        } else {
          throw new Error('Invalid POST request to /');
        }
      },
    );

    publicRouter.use(
      await createEntryPointRouter({
        appMode: 'public',
        logger: logger.child({ entry: 'public' }),
        rootDir: publicDistDir,
        assetStore: assetStore?.withNamespace('public'),
        appConfigs, // TODO(Rugvip): We should not be including the full config here
      }),
    );

    router.use(publicRouter);
  }

  router.use(
    await createEntryPointRouter({
      appMode: enablePublicEntryPoint ? 'protected' : 'public',
      logger: logger.child({ entry: 'main' }),
      rootDir: appDistDir,
      assetStore,
      staticFallbackHandler,
      appConfigs,
    }),
  );

  return router;
}

async function injectAppMode(options: {
  appMode: 'public' | 'protected';
  rootDir: string;
}) {
  const { appMode, rootDir } = options;
  const content = await fs.readFile(resolvePath(rootDir, 'index.html'), 'utf8');

  const metaTag = `<meta name="backstage-app-mode" content="${appMode}">`;

  let newContent;
  if (content.includes('backstage-app-mode')) {
    newContent = content.replace(
      /<meta name="backstage-app-mode" content="[^"]+">/,
      metaTag,
    );
  } else {
    newContent = content.replace(/<head>/, `<head>${metaTag}`);
  }

  await fs.writeFile(resolvePath(rootDir, 'index.html'), newContent, 'utf8');
}

async function createEntryPointRouter({
  logger,
  rootDir,
  assetStore,
  staticFallbackHandler,
  appMode,
  appConfigs,
}: {
  logger: Logger;
  rootDir: string;
  assetStore?: StaticAssetsStore;
  staticFallbackHandler?: express.Handler;
  appMode: 'public' | 'protected';
  appConfigs?: AppConfig[];
}) {
  const staticDir = resolvePath(rootDir, 'static');

  const injectedConfigPath =
    appConfigs && (await injectConfig({ appConfigs, logger, staticDir }));

  await injectAppMode({ appMode, rootDir });

  const router = Router();

  // Use a separate router for static content so that a fallback can be provided by backend
  const staticRouter = Router();
  staticRouter.use(
    express.static(staticDir, {
      setHeaders: (res, path) => {
        if (path === injectedConfigPath) {
          res.setHeader('Cache-Control', CACHE_CONTROL_REVALIDATE_CACHE);
        } else {
          res.setHeader('Cache-Control', CACHE_CONTROL_MAX_CACHE);
        }
      },
    }),
  );

  if (assetStore) {
    const assets = await findStaticAssets(staticDir);
    await assetStore.storeAssets(assets);
    // Remove any assets that are older than 7 days
    await assetStore.trimAssets({ maxAgeSeconds: 60 * 60 * 24 * 7 });

    staticRouter.use(createStaticAssetMiddleware(assetStore));
  }

  if (staticFallbackHandler) {
    staticRouter.use(staticFallbackHandler);
  }
  staticRouter.use(notFoundHandler());

  router.use('/static', staticRouter);
  router.use(
    express.static(rootDir, {
      setHeaders: (res, path) => {
        // The Cache-Control header instructs the browser to not cache html files since it might
        // link to static assets from recently deployed versions.
        if (
          (express.static.mime as unknown as Mime).lookup(path) === 'text/html'
        ) {
          res.setHeader('Cache-Control', CACHE_CONTROL_NO_CACHE);
        }
      },
    }),
  );

  router.get('/*', (_req, res) => {
    res.sendFile(resolvePath(rootDir, 'index.html'), {
      headers: {
        // The Cache-Control header instructs the browser to not cache the index.html since it might
        // link to static assets from recently deployed versions.
        'cache-control': CACHE_CONTROL_NO_CACHE,
      },
    });
  });

  return router;
}

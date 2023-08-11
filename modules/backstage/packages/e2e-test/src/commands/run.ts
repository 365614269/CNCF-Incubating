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

import os from 'os';
import fs from 'fs-extra';
import fetch from 'cross-fetch';
import handlebars from 'handlebars';
import killTree from 'tree-kill';
import { resolve as resolvePath, join as joinPath } from 'path';
import puppeteer from 'puppeteer';
import path from 'path';

import {
  spawnPiped,
  runPlain,
  waitForPageWithText,
  waitFor,
  waitForExit,
  print,
} from '../lib/helpers';
import pgtools from 'pgtools';
import { findPaths } from '@backstage/cli-common';

// eslint-disable-next-line no-restricted-syntax
const paths = findPaths(__dirname);

const templatePackagePaths = [
  'packages/cli/templates/default-plugin/package.json.hbs',
  'packages/create-app/templates/default-app/packages/app/package.json.hbs',
  'packages/create-app/templates/default-app/packages/backend/package.json.hbs',
];

export async function run() {
  const rootDir = await fs.mkdtemp(resolvePath(os.tmpdir(), 'backstage-e2e-'));
  print(`CLI E2E test root: ${rootDir}\n`);

  print('Building dist workspace');
  const workspaceDir = await buildDistWorkspace('workspace', rootDir);

  // Otherwise yarn will refuse to install with CI=true
  process.env.YARN_ENABLE_IMMUTABLE_INSTALLS = 'false';

  print('Creating a Backstage App');
  const appDir = await createApp('test-app', workspaceDir, rootDir);

  print('Creating a Backstage Plugin');
  const pluginId = 'test';
  await createPlugin({ appDir, pluginId, select: 'plugin' });

  print('Creating a Backstage Backend Plugin');
  await createPlugin({ appDir, pluginId, select: 'backend-plugin' });

  print('Starting the app');
  await testAppServe(pluginId, appDir);

  if (Boolean(process.env.POSTGRES_USER)) {
    print('Testing the PostgreSQL backend startup');
    await preCleanPostgres();
    const appConfig = path.resolve(appDir, 'app-config.yaml');
    const productionConfig = path.resolve(appDir, 'app-config.production.yaml');
    await testBackendStart(
      appDir,
      '--config',
      appConfig,
      '--config',
      productionConfig,
    );
  }
  print('Testing the SQLite backend startup');
  await testBackendStart(appDir);

  if (process.env.CI) {
    // Cleanup actually takes significant time, so skip it in CI since the
    // runner will be destroyed anyway
    print('All tests successful');
  } else {
    print('All tests successful, removing test dir');
    await fs.remove(rootDir);
  }

  // Just in case some child process was left hanging
  process.exit(0);
}

/**
 * Builds a dist workspace that contains the cli and core packages
 */
async function buildDistWorkspace(workspaceName: string, rootDir: string) {
  const workspaceDir = resolvePath(rootDir, workspaceName);
  await fs.ensureDir(workspaceDir);

  // We grab the needed dependencies from the create app template
  const createAppDeps = new Set<string>();

  function appendDeps(pkg: any) {
    Array<string>()
      .concat(
        Object.keys(pkg.dependencies ?? {}),
        Object.keys(pkg.devDependencies ?? {}),
        Object.keys(pkg.peerDependencies ?? {}),
      )
      .filter(name => name.startsWith('@backstage/'))
      .forEach(dep => createAppDeps.add(dep));
  }

  for (const pkgJsonPath of templatePackagePaths) {
    const jsonPath = paths.resolveOwnRoot(pkgJsonPath);
    const pkgTemplate = await fs.readFile(jsonPath, 'utf8');
    const pkg = JSON.parse(
      handlebars.compile(pkgTemplate)(
        {
          privatePackage: true,
          scopeName: '@backstage',
        },
        {
          helpers: {
            version(name: string) {
              // Ignore non Backstage packages
              if (!name.startsWith('@backstage/')) {
                return '^0.0.0';
              }
              const pkge = require(`${name}/package.json`);
              if (!pkge) {
                throw new Error(`No version available for package ${name}`);
              }
              return pkge.version;
            },
            versionQuery(name: string, hint: string) {
              // Ignore non Backstage packages
              if (!name.startsWith('@backstage/')) {
                return '^0.0.0';
              }
              const pkgData = require(`${name}/package.json`);
              if (!pkgData) {
                if (typeof hint !== 'string') {
                  throw new Error(`No version available for package ${name}`);
                }
                return `^${hint}`;
              }
              return `^${pkgData.version}`;
            },
          },
        },
      ),
    );
    appendDeps(pkg);
  }

  // eslint-disable-next-line @backstage/no-forbidden-package-imports
  appendDeps(require('@backstage/create-app/package.json'));

  print(`Preparing workspace`);
  await runPlain([
    'yarn',
    'backstage-cli',
    'build-workspace',
    workspaceDir,
    '@backstage/create-app',
    ...createAppDeps,
  ]);

  print('Pinning yarn version in workspace');
  await pinYarnVersion(workspaceDir);

  print('Installing workspace dependencies');
  await runPlain(['yarn', 'workspaces', 'focus', '--all', '--production'], {
    cwd: workspaceDir,
  });

  return workspaceDir;
}

/**
 * Pin the yarn version in a directory to the one we're using in the Backstage repo
 */
async function pinYarnVersion(dir: string) {
  const yarnRc = await fs.readFile(paths.resolveOwnRoot('.yarnrc.yml'), 'utf8');
  const yarnRcLines = yarnRc.split('\n');
  const yarnPathLine = yarnRcLines.find(line => line.startsWith('yarnPath:'));
  if (!yarnPathLine) {
    throw new Error(`Unable to find 'yarnPath' in ${yarnRc}`);
  }
  const match = yarnPathLine.match(/^yarnPath: (.*)$/);
  if (!match) {
    throw new Error(`Invalid 'yarnPath' in ${yarnRc}`);
  }
  const [, localYarnPath] = match;
  const yarnPath = paths.resolveOwnRoot(localYarnPath);
  const yarnPluginPath = paths.resolveOwnRoot(
    localYarnPath,
    '../../plugins/@yarnpkg/plugin-workspace-tools.cjs',
  );

  await fs.writeFile(
    resolvePath(dir, '.yarnrc.yml'),
    `yarnPath: ${yarnPath}
nodeLinker: node-modules
enableGlobalCache: true
plugins:
  - path: ${yarnPluginPath}
    spec: '@yarnpkg/plugin-workspace-tools'
`,
  );
}

/**
 * Creates a new app inside rootDir called test-app, using packages from the workspaceDir
 */
async function createApp(
  appName: string,
  workspaceDir: string,
  rootDir: string,
) {
  const child = spawnPiped(
    [
      'node',
      resolvePath(workspaceDir, 'packages/create-app/bin/backstage-create-app'),
      '--skip-install',
    ],
    {
      cwd: rootDir,
    },
  );

  try {
    let stdout = '';
    child.stdout?.on('data', data => {
      stdout = stdout + data.toString('utf8');
    });

    await waitFor(() => stdout.includes('Enter a name for the app'));
    child.stdin?.write(`${appName}\n`);

    print('Waiting for app create script to be done');
    await waitForExit(child);

    const appDir = resolvePath(rootDir, appName);

    print('Rewriting module resolutions of app to use workspace packages');
    await overrideModuleResolutions(appDir, workspaceDir);

    // Yarn does not clean up node_module folders in the linked in dependencies by itself
    print('Cleaning up node_modules in workspace');
    await fs.remove(resolvePath(workspaceDir, 'node_modules'));
    for (const wsDir of ['packages', 'plugins']) {
      for (const dir of await fs.readdir(resolvePath(workspaceDir, wsDir))) {
        const moduleDir = resolvePath(workspaceDir, wsDir, dir, 'node_modules');
        if (await fs.pathExists(moduleDir)) {
          await fs.remove(moduleDir);
        }
      }
    }

    print('Pinning yarn version and registry in app');
    await pinYarnVersion(appDir);
    await fs.writeFile(
      resolvePath(appDir, '.npmrc'),
      'registry=https://registry.npmjs.org/\n',
    );

    print('Test app created');

    for (const cmd of [
      'install',
      'tsc:full',
      'build:all',
      'lint:all',
      'prettier:check',
      'test:all',
    ]) {
      print(`Running 'yarn ${cmd}' in newly created app`);
      await runPlain(['yarn', cmd], { cwd: appDir });
    }

    print(`Running 'yarn test:e2e:ci' in newly created app`);
    await runPlain(['yarn', 'test:e2e:ci'], {
      cwd: resolvePath(appDir, 'packages', 'app'),
      env: {
        ...process.env,
        APP_CONFIG_app_baseUrl: '"http://localhost:3001"',
      },
    });

    return appDir;
  } finally {
    child.kill();
  }
}

/**
 * This points dependency resolutions into the workspace for each package that is present there
 */
async function overrideModuleResolutions(appDir: string, workspaceDir: string) {
  const pkgJsonPath = resolvePath(appDir, 'package.json');
  const pkgJson = await fs.readJson(pkgJsonPath);

  pkgJson.resolutions = pkgJson.resolutions || {};
  pkgJson.dependencies = pkgJson.dependencies || {};

  for (const dir of ['packages', 'plugins']) {
    const packageNames = await fs.readdir(resolvePath(workspaceDir, dir));
    for (const pkgDir of packageNames) {
      const pkgPath = joinPath('..', 'workspace', dir, pkgDir);
      const { name } = await fs.readJson(
        resolvePath(workspaceDir, dir, pkgDir, 'package.json'),
      );

      pkgJson.dependencies[name] = `file:${pkgPath}`;
      pkgJson.resolutions[name] = `file:${pkgPath}`;
      delete pkgJson.devDependencies[name];
    }
  }
  fs.writeJson(pkgJsonPath, pkgJson, { spaces: 2 });
}

/**
 * Uses create-plugin command to create a new plugin in the app
 */
async function createPlugin(options: {
  appDir: string;
  pluginId: string;
  select: string;
}) {
  const { appDir, pluginId, select } = options;
  const child = spawnPiped(
    ['yarn', 'new', '--select', select, '--option', `id=${pluginId}`],
    {
      cwd: appDir,
    },
  );

  try {
    let stdout = '';
    child.stdout?.on('data', (data: Buffer) => {
      stdout = stdout + data.toString('utf8');
    });

    print('Waiting for plugin create script to be done');
    await waitForExit(child);

    const pluginDir = resolvePath(
      appDir,
      'plugins',
      select === 'backend-plugin' ? `${pluginId}-backend` : pluginId,
    );

    print(`Running 'yarn tsc' in root for newly created plugin`);
    await runPlain(['yarn', 'tsc'], { cwd: appDir });

    for (const cmd of [['lint'], ['test', '--no-watch']]) {
      print(`Running 'yarn ${cmd.join(' ')}' in newly created plugin`);
      await runPlain(['yarn', ...cmd], { cwd: pluginDir });
    }
  } finally {
    child.kill();
  }
}

/**
 * Start serving the newly created app and make sure that the create plugin is rendering correctly
 */
async function testAppServe(pluginId: string, appDir: string) {
  const startApp = spawnPiped(['yarn', 'start'], {
    cwd: appDir,
    env: {
      ...process.env,
      GITHUB_TOKEN: 'abc',
    },
  });

  let successful = false;

  let browser;
  try {
    for (let attempts = 1; ; attempts++) {
      try {
        browser = await puppeteer.launch();
        const page = await browser.newPage();

        await page.goto('http://localhost:3000', { waitUntil: 'networkidle0' });

        await waitForPageWithText(page, '/', 'My Company Catalog');
        await waitForPageWithText(
          page,
          `/${pluginId}`,
          `Welcome to ${pluginId}!`,
        );

        print('Both App and Plugin loaded correctly');
        successful = true;
        break;
      } catch (error) {
        if (attempts >= 20) {
          throw new Error(`App serve test failed, ${error}`);
        }
        print(`App serve failed, trying again, ${error}`);
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
  } finally {
    // Kill entire process group, otherwise we'll end up with hanging serve processes
    await new Promise<void>((res, rej) => {
      killTree(startApp.pid!, err => (err ? rej(err) : res()));
    });
  }

  try {
    await waitForExit(startApp);
  } catch (error) {
    if (!successful) {
      throw error;
    }
  }
}

/** Drops PG databases */
async function dropDB(database: string) {
  const config = {
    host: process.env.POSTGRES_HOST,
    port: process.env.POSTGRES_PORT,
    user: process.env.POSTGRES_USER,
    password: process.env.POSTGRES_PASSWORD,
  };

  try {
    await pgtools.dropdb(config, database);
  } catch (_) {
    /* do nothing*/
  }
}

/** Clean remnants from prior e2e runs */
async function preCleanPostgres() {
  print('Dropping old DBs');
  await Promise.all(
    [
      'catalog',
      'scaffolder',
      'auth',
      'identity',
      'proxy',
      'techdocs',
      'search',
    ].map(name => dropDB(`backstage_plugin_${name}`)),
  );
  print('Created DBs');
}

/**
 * Start serving the newly created backend and make sure that all db migrations works correctly
 */
async function testBackendStart(appDir: string, ...args: string[]) {
  const child = spawnPiped(['yarn', 'workspace', 'backend', 'start', ...args], {
    cwd: appDir,
    env: {
      ...process.env,
      GITHUB_TOKEN: 'abc',
    },
  });

  let stdout = '';
  let stderr = '';
  child.stdout?.on('data', (data: Buffer) => {
    stdout = stdout + data.toString('utf8');
  });
  child.stderr?.on('data', (data: Buffer) => {
    stderr = stderr + data.toString('utf8');
  });
  let successful = false;

  const stdErrorHasErrors = (input: string) => {
    const lines = input.split('\n').filter(Boolean);
    return (
      lines.filter(
        l =>
          !l.includes('Use of deprecated folder mapping') &&
          !l.includes('Update this package.json to use a subpath') &&
          !l.includes(
            '(Use `node --trace-deprecation ...` to show where the warning was created)',
          ) &&
          // These 4 are all for the AWS SDK v2 deprecation
          !l.includes(
            'The AWS SDK for JavaScript (v2) will be put into maintenance mode',
          ) &&
          !l.includes(
            'Please migrate your code to use AWS SDK for JavaScript',
          ) &&
          !l.includes('check the migration guide at https://a.co/7PzMCcy') &&
          !l.includes(
            '(Use `node --trace-warnings ...` to show where the warning was created)',
          ),
      ).length !== 0
    );
  };

  try {
    await waitFor(
      () => stdout.includes('Listening on ') || stdErrorHasErrors(stderr),
    );
    if (stdErrorHasErrors(stderr)) {
      print(`Expected stderr to be clean, got ${stderr}`);
      // Skipping the whole block
      throw new Error(stderr);
    }
    await new Promise(resolve => setTimeout(resolve, 500));

    print('Try to fetch entities from the backend');
    // Try fetch entities, should be ok
    await fetch('http://localhost:7007/api/catalog/entities').then(res =>
      res.json(),
    );
    print('Entities fetched successfully');
    successful = true;
  } catch (error) {
    print('');
    throw new Error(`Backend failed to startup: ${error}`);
  } finally {
    print('Stopping the child process');
    // Kill entire process group, otherwise we'll end up with hanging serve processes
    await new Promise<void>((res, rej) => {
      killTree(child.pid!, err => (err ? rej(err) : res()));
    });
  }

  try {
    await waitForExit(child);
  } catch (error) {
    if (!successful) {
      throw new Error(`Backend failed to startup: ${stderr}`);
    }
    print('Backend startup test finished successfully');
  }
}

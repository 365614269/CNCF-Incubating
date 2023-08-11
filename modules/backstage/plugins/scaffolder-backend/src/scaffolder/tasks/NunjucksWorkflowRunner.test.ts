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

import mockFs from 'mock-fs';
import * as winston from 'winston';

import { getVoidLogger, resolvePackagePath } from '@backstage/backend-common';
import { NunjucksWorkflowRunner } from './NunjucksWorkflowRunner';
import { TemplateActionRegistry } from '../actions';
import { ScmIntegrations } from '@backstage/integration';
import { ConfigReader } from '@backstage/config';
import { TaskContext } from './types';
import { TaskSpec } from '@backstage/plugin-scaffolder-common';
import {
  createTemplateAction,
  TaskSecrets,
  TemplateAction,
} from '@backstage/plugin-scaffolder-node';
import { UserEntity } from '@backstage/catalog-model';
import { z } from 'zod';
import {
  AuthorizeResult,
  PermissionEvaluator,
} from '@backstage/plugin-permission-common';
import { RESOURCE_TYPE_SCAFFOLDER_ACTION } from '@backstage/plugin-scaffolder-common/alpha';

// The Stream module is lazy loaded, so make sure it's in the module cache before mocking fs
void winston.transports.Stream;

const realFiles = Object.fromEntries(
  [
    resolvePackagePath(
      '@backstage/plugin-scaffolder-backend',
      'assets',
      'nunjucks.js.txt',
    ),
  ].map(k => [k, mockFs.load(k)]),
);

describe('DefaultWorkflowRunner', () => {
  const logger = getVoidLogger();
  let actionRegistry = new TemplateActionRegistry();
  let runner: NunjucksWorkflowRunner;
  let fakeActionHandler: jest.Mock;

  const mockedPermissionApi: jest.Mocked<PermissionEvaluator> = {
    authorizeConditional: jest.fn(),
  } as unknown as jest.Mocked<PermissionEvaluator>;

  const integrations = ScmIntegrations.fromConfig(
    new ConfigReader({
      integrations: {
        github: [{ host: 'github.com', token: 'token' }],
      },
    }),
  );

  const createMockTaskWithSpec = (
    spec: TaskSpec,
    secrets?: TaskSecrets,
    isDryRun?: boolean,
  ): TaskContext => ({
    spec,
    secrets,
    isDryRun,
    complete: async () => {},
    done: false,
    emitLog: async () => {},
    cancelSignal: new AbortController().signal,
    getWorkspaceName: () => Promise.resolve('test-workspace'),
  });

  beforeEach(() => {
    winston.format.simple(); // put logform in the require.cache before mocking fs
    mockFs({
      '/tmp': mockFs.directory(),
      ...realFiles,
    });

    jest.resetAllMocks();
    actionRegistry = new TemplateActionRegistry();
    fakeActionHandler = jest.fn();

    actionRegistry.register({
      id: 'jest-mock-action',
      description: 'Mock action for testing',
      handler: fakeActionHandler,
    });

    actionRegistry.register({
      id: 'jest-validated-action',
      description: 'Mock action for testing',
      supportsDryRun: true,
      handler: fakeActionHandler,
      schema: {
        input: {
          type: 'object',
          required: ['foo'],
          properties: {
            foo: {
              type: 'number',
            },
          },
        },
      },
    });

    actionRegistry.register(
      createTemplateAction({
        id: 'jest-zod-validated-action',
        description: 'Mock action for testing',
        handler: fakeActionHandler,
        supportsDryRun: true,
        schema: {
          input: z.object({
            foo: z.number(),
          }),
        },
      }) as TemplateAction,
    );

    actionRegistry.register({
      id: 'output-action',
      description: 'Mock action for testing',
      handler: async ctx => {
        ctx.output('mock', 'backstage');
        ctx.output('shouldRun', true);
      },
    });

    mockedPermissionApi.authorizeConditional.mockResolvedValue([
      { result: AuthorizeResult.ALLOW },
    ]);

    runner = new NunjucksWorkflowRunner({
      actionRegistry,
      integrations,
      workingDirectory: '/tmp',
      logger,
      permissions: mockedPermissionApi,
    });
  });

  afterEach(() => {
    mockFs.restore();
  });

  it('should throw an error if the action does not exist', async () => {
    const task = createMockTaskWithSpec({
      apiVersion: 'scaffolder.backstage.io/v1beta3',
      parameters: {},
      output: {},
      steps: [{ id: 'test', name: 'name', action: 'does-not-exist' }],
    });

    await expect(runner.execute(task)).rejects.toThrow(
      "Template action with ID 'does-not-exist' is not registered.",
    );
  });

  describe('validation', () => {
    it('should throw an error if the action has a schema and the input does not match', async () => {
      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        parameters: {},
        output: {},
        steps: [{ id: 'test', name: 'name', action: 'jest-validated-action' }],
      });

      await expect(runner.execute(task)).rejects.toThrow(
        /Invalid input passed to action jest-validated-action, instance requires property "foo"/,
      );
    });

    it('should throw an error if the action has a zod schema and the input does not match', async () => {
      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        parameters: {},
        output: {},
        steps: [
          { id: 'test', name: 'name', action: 'jest-zod-validated-action' },
        ],
      });

      await expect(runner.execute(task)).rejects.toThrow(
        /Invalid input passed to action jest-zod-validated-action, instance requires property \"foo\"/,
      );
    });

    it('should run the action when the zod validation passes', async () => {
      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        parameters: {},
        output: {},
        steps: [
          {
            id: 'test',
            name: 'name',
            action: 'jest-zod-validated-action',
            input: { foo: 1 },
          },
        ],
      });

      await runner.execute(task);

      expect(fakeActionHandler).toHaveBeenCalledTimes(1);
    });

    it('should run the action when the validation passes', async () => {
      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        parameters: {},
        output: {},
        steps: [
          {
            id: 'test',
            name: 'name',
            action: 'jest-validated-action',
            input: { foo: 1 },
          },
        ],
      });

      await runner.execute(task);

      expect(fakeActionHandler).toHaveBeenCalledTimes(1);
    });

    it('should pass metadata through', async () => {
      const entityRef = `template:default/templateName`;

      const userEntity: UserEntity = {
        apiVersion: 'backstage.io/v1beta1',
        kind: 'User',
        metadata: {
          name: 'user',
        },
        spec: {
          profile: {
            displayName: 'Bogdan Nechyporenko',
            email: 'bnechyporenko@company.com',
          },
        },
      };

      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        parameters: {},
        output: {},
        steps: [
          {
            id: 'test',
            name: 'name',
            action: 'jest-validated-action',
            input: { foo: 1 },
          },
        ],
        templateInfo: { entityRef },
        user: {
          entity: userEntity,
        },
      });

      await runner.execute(task);

      expect(fakeActionHandler.mock.calls[0][0].templateInfo).toEqual({
        entityRef,
      });

      expect(fakeActionHandler.mock.calls[0][0].user).toEqual({
        entity: userEntity,
      });
    });

    it('should pass token through', async () => {
      const fakeToken = 'secret';
      const task = createMockTaskWithSpec(
        {
          apiVersion: 'scaffolder.backstage.io/v1beta3',
          parameters: {},
          output: {},
          steps: [
            {
              id: 'test',
              name: 'name',
              action: 'jest-validated-action',
              input: { foo: 1 },
            },
          ],
        },
        {
          backstageToken: fakeToken,
        },
      );

      await runner.execute(task);

      expect(fakeActionHandler.mock.calls[0][0].secrets).toEqual(
        expect.objectContaining({ backstageToken: fakeToken }),
      );
    });
  });

  describe('conditionals', () => {
    it('should execute steps conditionally', async () => {
      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        steps: [
          { id: 'test', name: 'test', action: 'output-action' },
          {
            id: 'conditional',
            name: 'conditional',
            action: 'output-action',
            if: '${{ steps.test.output.shouldRun }}',
          },
        ],
        output: {
          result: '${{ steps.conditional.output.mock }}',
        },
        parameters: {},
      });

      const { output } = await runner.execute(task);

      expect(output.result).toBe('backstage');
    });

    it('should skips steps conditionally', async () => {
      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        steps: [
          { id: 'test', name: 'test', action: 'output-action' },
          {
            id: 'conditional',
            name: 'conditional',
            action: 'output-action',
            if: '${{ not steps.test.output.shouldRun}}',
          },
        ],
        output: {
          result: '${{ steps.conditional.output.mock }}',
        },
        parameters: {},
      });

      const { output } = await runner.execute(task);

      expect(output.result).toBeUndefined();
    });

    it('should skips steps using the negating equals operator', async () => {
      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        steps: [
          { id: 'test', name: 'test', action: 'output-action' },
          {
            id: 'conditional',
            name: 'conditional',
            action: 'output-action',
            if: '${{ steps.test.output.mock !== "backstage"}}',
          },
        ],
        output: {
          result: '${{ steps.conditional.output.mock }}',
        },
        parameters: {},
      });

      const { output } = await runner.execute(task);

      expect(output.result).toBeUndefined();
    });
  });

  describe('templating', () => {
    it('should template the input to an action', async () => {
      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        steps: [
          {
            id: 'test',
            name: 'name',
            action: 'jest-mock-action',
            input: {
              foo: '${{parameters.input | lower }}',
            },
          },
        ],
        output: {},
        parameters: {
          input: 'BACKSTAGE',
        },
      });

      await runner.execute(task);

      expect(fakeActionHandler).toHaveBeenCalledWith(
        expect.objectContaining({ input: { foo: 'backstage' } }),
      );
    });

    it('should not try and parse something that is not parsable', async () => {
      jest.spyOn(logger, 'error');
      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        steps: [
          {
            id: 'test',
            name: 'name',
            action: 'jest-mock-action',
            input: {
              foo: 'bob',
            },
          },
        ],
        output: {},
        parameters: {
          input: 'BACKSTAGE',
        },
      });

      await runner.execute(task);

      expect(logger.error).not.toHaveBeenCalled();
    });

    it('should keep the original types for the input and not parse things that are not meant to be parsed', async () => {
      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        steps: [
          {
            id: 'test',
            name: 'name',
            action: 'jest-mock-action',
            input: {
              number: '${{parameters.number}}',
              string: '${{parameters.string}}',
            },
          },
        ],
        output: {},
        parameters: {
          number: 0,
          string: '1',
        },
      });

      await runner.execute(task);

      expect(fakeActionHandler).toHaveBeenCalledWith(
        expect.objectContaining({ input: { number: 0, string: '1' } }),
      );
    });

    it('should template complex values into the action', async () => {
      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        steps: [
          {
            id: 'test',
            name: 'name',
            action: 'jest-mock-action',
            input: {
              foo: '${{parameters.complex}}',
            },
          },
        ],
        output: {},
        parameters: {
          complex: { bar: 'BACKSTAGE' },
        },
      });

      await runner.execute(task);

      expect(fakeActionHandler).toHaveBeenCalledWith(
        expect.objectContaining({ input: { foo: { bar: 'BACKSTAGE' } } }),
      );
    });

    it('supports really complex structures', async () => {
      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        steps: [
          {
            id: 'test',
            name: 'name',
            action: 'jest-mock-action',
            input: {
              foo: '${{parameters.complex.baz.something}}',
            },
          },
        ],
        output: {},
        parameters: {
          complex: {
            bar: 'BACKSTAGE',
            baz: { something: 'nested', here: 'yas' },
          },
        },
      });

      await runner.execute(task);

      expect(fakeActionHandler).toHaveBeenCalledWith(
        expect.objectContaining({ input: { foo: 'nested' } }),
      );
    });

    it('supports numbers as first class too', async () => {
      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        steps: [
          {
            id: 'test',
            name: 'name',
            action: 'jest-mock-action',
            input: {
              foo: '${{parameters.complex.baz.number}}',
            },
          },
        ],
        output: {},
        parameters: {
          complex: {
            bar: 'BACKSTAGE',
            baz: { number: 1 },
          },
        },
      });

      await runner.execute(task);

      expect(fakeActionHandler).toHaveBeenCalledWith(
        expect.objectContaining({ input: { foo: 1 } }),
      );
    });

    it('should template the output from simple actions', async () => {
      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        steps: [
          {
            id: 'test',
            name: 'name',
            action: 'output-action',
            input: {},
          },
        ],
        output: {
          foo: '${{steps.test.output.mock | upper}}',
        },
        parameters: {},
      });

      const { output } = await runner.execute(task);

      expect(output.foo).toEqual('BACKSTAGE');
    });
  });

  describe('secrets', () => {
    it('should pass through the secrets to the context', async () => {
      const task = createMockTaskWithSpec(
        {
          apiVersion: 'scaffolder.backstage.io/v1beta3',
          steps: [
            {
              id: 'test',
              name: 'name',
              action: 'jest-mock-action',
              input: {},
            },
          ],
          output: {},
          parameters: {},
        },
        { foo: 'bar' },
      );

      await runner.execute(task);

      expect(fakeActionHandler).toHaveBeenCalledWith(
        expect.objectContaining({ secrets: { foo: 'bar' } }),
      );
    });

    it('should be able to template secrets into the input of an action', async () => {
      const task = createMockTaskWithSpec(
        {
          apiVersion: 'scaffolder.backstage.io/v1beta3',
          steps: [
            {
              id: 'test',
              name: 'name',
              action: 'jest-mock-action',
              input: {
                b: '${{ secrets.foo }}',
              },
            },
          ],
          output: {},
          parameters: {},
        },
        { foo: 'bar' },
      );

      await runner.execute(task);

      expect(fakeActionHandler).toHaveBeenCalledWith(
        expect.objectContaining({ input: { b: 'bar' } }),
      );
    });

    it('does not allow templating of secrets as an output', async () => {
      const task = createMockTaskWithSpec(
        {
          apiVersion: 'scaffolder.backstage.io/v1beta3',
          steps: [
            {
              id: 'test',
              name: 'name',
              action: 'jest-mock-action',
              input: {
                b: '${{ secrets.foo }}',
              },
            },
          ],
          output: {
            b: '${{ secrets.foo }}',
          },
          parameters: {},
        },
        { foo: 'bar' },
      );

      const executedTask = await runner.execute(task);

      expect(executedTask.output.b).toBeUndefined();
    });
  });

  describe('user', () => {
    it('allows access to the user entity at the templating level', async () => {
      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        steps: [
          {
            id: 'test',
            name: 'name',
            action: 'output-action',
            input: {},
          },
        ],
        user: {
          entity: { metadata: { name: 'bob' } } as UserEntity,
          ref: 'user:default/guest',
        },
        output: {
          foo: '${{ user.entity.metadata.name }} ${{ user.ref }}',
        },
        parameters: {
          repoUrl: 'github.com?repo=repo&owner=owner',
        },
      });

      const { output } = await runner.execute(task);

      expect(output.foo).toEqual('bob user:default/guest');
    });
  });

  describe('filters', () => {
    it('provides the parseRepoUrl filter', async () => {
      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        steps: [
          {
            id: 'test',
            name: 'name',
            action: 'output-action',
            input: {},
          },
        ],
        output: {
          foo: '${{ parameters.repoUrl | parseRepoUrl }}',
        },
        parameters: {
          repoUrl: 'github.com?repo=repo&owner=owner',
        },
      });

      const { output } = await runner.execute(task);

      expect(output.foo).toEqual({
        host: 'github.com',
        owner: 'owner',
        repo: 'repo',
      });
    });

    it('provides the parseEntityRef filter', async () => {
      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        steps: [
          {
            id: 'test',
            name: 'name',
            action: 'output-action',
            input: {},
          },
        ],
        output: {
          foo: '${{ parameters.entity | parseEntityRef }}',
        },
        parameters: {
          entity: 'component:default/ben',
        },
      });

      const { output } = await runner.execute(task);

      expect(output.foo).toEqual({
        kind: 'component',
        namespace: 'default',
        name: 'ben',
      });
    });

    it('provides the pick filter', async () => {
      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        steps: [
          {
            id: 'test',
            name: 'name',
            action: 'output-action',
            input: {},
          },
        ],
        output: {
          foo: '${{ parameters.entity | parseEntityRef | pick("kind") }}',
        },
        parameters: {
          entity: 'component:default/ben',
        },
      });

      const { output } = await runner.execute(task);

      expect(output.foo).toEqual('component');
    });

    it('should allow deep nesting of picked objects', async () => {
      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        steps: [
          {
            id: 'test',
            name: 'name',
            action: 'output-action',
            input: {},
          },
        ],
        output: {
          foo: '${{ parameters.entity | pick("something.deeply.nested") }}',
        },
        parameters: {
          entity: {
            something: {
              deeply: {
                nested: 'component',
              },
            },
          },
        },
      });

      const { output } = await runner.execute(task);

      expect(output.foo).toEqual('component');
    });
  });

  describe('dry run', () => {
    it('sets isDryRun flag correctly', async () => {
      const task = createMockTaskWithSpec(
        {
          apiVersion: 'scaffolder.backstage.io/v1beta3',
          parameters: {},
          output: {},
          steps: [
            {
              id: 'test',
              name: 'name',
              action: 'jest-validated-action',
              input: { foo: 1 },
            },
          ],
        },
        {
          backstageToken: 'secret',
        },
        true,
      );

      await runner.execute(task);

      expect(fakeActionHandler.mock.calls[0][0].isDryRun).toEqual(true);
    });
  });

  describe('permissions', () => {
    it('should throw an error if an actions is not authorized', async () => {
      mockedPermissionApi.authorizeConditional.mockResolvedValueOnce([
        { result: AuthorizeResult.DENY },
      ]);

      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        parameters: {},
        output: {},
        steps: [
          {
            id: 'test',
            name: 'name',
            action: 'jest-validated-action',
            input: { foo: 1 },
          },
        ],
      });

      await expect(runner.execute(task)).rejects.toThrow(
        /Unauthorized action: jest-validated-action. The action is not allowed/,
      );
      expect(fakeActionHandler).not.toHaveBeenCalled();
    });

    it(`shouldn't execute actions who aren't authorized`, async () => {
      mockedPermissionApi.authorizeConditional.mockResolvedValueOnce([
        {
          result: AuthorizeResult.CONDITIONAL,
          pluginId: 'scaffolder',
          resourceType: RESOURCE_TYPE_SCAFFOLDER_ACTION,
          conditions: {
            anyOf: [
              {
                resourceType: RESOURCE_TYPE_SCAFFOLDER_ACTION,
                rule: 'HAS_NUMBER_PROPERTY',
                params: {
                  key: 'foo',
                  value: 1,
                },
              },
            ],
          },
        },
      ]);

      const task = createMockTaskWithSpec({
        apiVersion: 'scaffolder.backstage.io/v1beta3',
        parameters: {},
        output: {},
        steps: [
          {
            id: 'test1',
            name: 'valid action',
            action: 'jest-validated-action',
            input: { foo: 1 },
          },
          {
            id: 'test2',
            name: 'invalid action',
            action: 'jest-validated-action',
            input: { foo: 2 },
          },
        ],
      });

      await expect(runner.execute(task)).rejects.toThrow(
        `Unauthorized action: jest-validated-action. The action is not allowed. Input: ${JSON.stringify(
          { foo: 2 },
          null,
          2,
        )}`,
      );
      expect(fakeActionHandler).toHaveBeenCalled();
      expect(mockedPermissionApi.authorizeConditional).toHaveBeenCalledTimes(1);
    });
  });
});

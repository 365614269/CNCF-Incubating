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

import { getVoidLogger } from '@backstage/backend-common';
import {
  PluginTaskScheduler,
  TaskInvocationDefinition,
  TaskRunner,
} from '@backstage/backend-tasks';
import { setupRequestMockHandlers } from '@backstage/backend-test-utils';
import { ConfigReader } from '@backstage/config';
import { EntityProviderConnection } from '@backstage/plugin-catalog-node';
import { graphql, rest } from 'msw';
import { setupServer } from 'msw/node';
import { GitlabOrgDiscoveryEntityProvider } from './GitlabOrgDiscoveryEntityProvider';

class PersistingTaskRunner implements TaskRunner {
  private tasks: TaskInvocationDefinition[] = [];

  getTasks() {
    return this.tasks;
  }

  run(task: TaskInvocationDefinition): Promise<void> {
    this.tasks.push(task);
    return Promise.resolve(undefined);
  }
}

const logger = getVoidLogger();

const server = setupServer();

describe('GitlabOrgDiscoveryEntityProvider', () => {
  setupRequestMockHandlers(server);
  afterEach(() => jest.resetAllMocks());

  it('no provider config', () => {
    const schedule = new PersistingTaskRunner();
    const config = new ConfigReader({});
    const providers = GitlabOrgDiscoveryEntityProvider.fromConfig(config, {
      logger,
      schedule,
    });

    expect(providers).toHaveLength(0);
  });

  it('single simple discovery config with org disabled', () => {
    const schedule = new PersistingTaskRunner();
    const config = new ConfigReader({
      integrations: {
        gitlab: [
          {
            host: 'test-gitlab',
            apiBaseUrl: 'https://api.gitlab.example/api/v4',
            token: '1234',
          },
        ],
      },
      catalog: {
        providers: {
          gitlab: {
            'test-id': {
              host: 'test-gitlab',
              group: 'test-group',
            },
          },
        },
      },
    });
    const providers = GitlabOrgDiscoveryEntityProvider.fromConfig(config, {
      logger,
      schedule,
    });

    expect(providers).toHaveLength(0);
  });

  it('single simple discovery config with org enabled', () => {
    const schedule = new PersistingTaskRunner();
    const config = new ConfigReader({
      integrations: {
        gitlab: [
          {
            host: 'test-gitlab',
            apiBaseUrl: 'https://api.gitlab.example/api/v4',
            token: '1234',
          },
        ],
      },
      catalog: {
        providers: {
          gitlab: {
            'test-id': {
              host: 'test-gitlab',
              group: 'test-group',
              orgEnabled: true,
            },
          },
        },
      },
    });
    const providers = GitlabOrgDiscoveryEntityProvider.fromConfig(config, {
      logger,
      schedule,
    });

    expect(providers).toHaveLength(1);
    expect(providers[0].getProviderName()).toEqual(
      'GitlabOrgDiscoveryEntityProvider:test-id',
    );
  });

  it('multiple discovery configs', () => {
    const schedule = new PersistingTaskRunner();
    const config = new ConfigReader({
      integrations: {
        gitlab: [
          {
            host: 'test-gitlab',
            apiBaseUrl: 'https://api.gitlab.example/api/v4',
            token: '1234',
          },
        ],
      },
      catalog: {
        providers: {
          gitlab: {
            'test-id': {
              host: 'test-gitlab',
              group: 'test-group',
              orgEnabled: true,
            },
            'second-test': {
              host: 'test-gitlab',
              group: 'second-group',
              orgEnabled: true,
            },
          },
        },
      },
    });
    const providers = GitlabOrgDiscoveryEntityProvider.fromConfig(config, {
      logger,
      schedule,
    });

    expect(providers).toHaveLength(2);
    expect(providers[0].getProviderName()).toEqual(
      'GitlabOrgDiscoveryEntityProvider:test-id',
    );
    expect(providers[1].getProviderName()).toEqual(
      'GitlabOrgDiscoveryEntityProvider:second-test',
    );
  });

  it('apply full update on scheduled execution', async () => {
    const config = new ConfigReader({
      integrations: {
        gitlab: [
          {
            host: 'test-gitlab',
            apiBaseUrl: 'https://api.gitlab.example/api/v4',
            token: '1234',
          },
        ],
      },
      catalog: {
        providers: {
          gitlab: {
            'test-id': {
              host: 'test-gitlab',
              orgEnabled: true,
            },
          },
        },
      },
    });
    const schedule = new PersistingTaskRunner();
    const entityProviderConnection: EntityProviderConnection = {
      applyMutation: jest.fn(),
      refresh: jest.fn(),
    };
    const provider = GitlabOrgDiscoveryEntityProvider.fromConfig(config, {
      logger,
      schedule,
    })[0];
    expect(provider.getProviderName()).toEqual(
      'GitlabOrgDiscoveryEntityProvider:test-id',
    );

    server.use(
      rest.get(
        `https://api.gitlab.example/api/v4/groups/test-group/projects`,
        (_req, res, ctx) => {
          const response = [
            {
              id: 123,
              default_branch: 'master',
              archived: false,
              last_activity_at: new Date().toString(),
              web_url: 'https://api.gitlab.example/test-group/test-repo',
              path_with_namespace: 'test-group/test-repo',
            },
          ];
          return res(ctx.json(response));
        },
      ),
      rest.get(`https://api.gitlab.example/api/v4/users`, (_req, res, ctx) => {
        const response = [
          {
            id: 1,
            username: 'test1',
            name: 'Test Testit',
            state: 'active',
            avatar_url: 'https://secure.gravatar.com/',
            web_url: 'https://gitlab.example/test1',
            created_at: '2023-01-19T07:27:03.333Z',
            bio: '',
            location: null,
            public_email: null,
            skype: '',
            linkedin: '',
            twitter: '',
            website_url: '',
            organization: null,
            job_title: '',
            pronouns: null,
            bot: false,
            work_information: null,
            followers: 0,
            following: 0,
            is_followed: false,
            local_time: null,
            last_sign_in_at: '2023-01-19T07:27:49.601Z',
            confirmed_at: '2023-01-19T07:27:02.905Z',
            last_activity_on: '2023-01-19',
            email: 'test@example.com',
            theme_id: 1,
            color_scheme_id: 1,
            projects_limit: 100000,
            current_sign_in_at: '2023-01-19T09:09:10.676Z',
            identities: [],
            can_create_group: true,
            can_create_project: true,
            two_factor_enabled: false,
            external: false,
            private_profile: false,
            commit_email: 'test@example.com',
            is_admin: false,
            note: '',
          },
          {
            id: 2,
            username: 'test2',
            name: '',
            state: 'active',
            avatar_url: '',
            web_url: 'https://gitlab.example/test2',
            created_at: '2023-01-19T07:27:03.333Z',
            bio: '',
            location: null,
            public_email: null,
            skype: '',
            linkedin: '',
            twitter: '',
            website_url: '',
            organization: null,
            job_title: '',
            pronouns: null,
            bot: false,
            work_information: null,
            followers: 0,
            following: 0,
            is_followed: false,
            local_time: null,
            last_sign_in_at: '2023-01-19T07:27:49.601Z',
            confirmed_at: '2023-01-19T07:27:02.905Z',
            last_activity_on: '2023-01-19',
            email: 'test@example.com',
            theme_id: 1,
            color_scheme_id: 1,
            projects_limit: 100000,
            current_sign_in_at: '2023-01-19T09:09:10.676Z',
            identities: [],
            can_create_group: true,
            can_create_project: true,
            two_factor_enabled: false,
            external: false,
            private_profile: false,
            commit_email: 'test@example.com',
            is_admin: false,
            note: '',
          },
        ];
        return res(ctx.json(response));
      }),
      rest.get(`https://api.gitlab.example/api/v4/groups`, (_req, res, ctx) => {
        const response = [
          {
            id: 1,
            web_url: 'https://gitlab.example/groups/group1',
            name: 'group1',
            path: 'group1',
            description: '',
            visibility: 'internal',
            share_with_group_lock: false,
            require_two_factor_authentication: false,
            two_factor_grace_period: 48,
            project_creation_level: 'developer',
            auto_devops_enabled: null,
            subgroup_creation_level: 'owner',
            emails_disabled: null,
            mentions_disabled: null,
            lfs_enabled: true,
            default_branch_protection: 2,
            avatar_url: null,
            request_access_enabled: false,
            full_name: '8020',
            full_path: '8020',
            created_at: '2017-06-19T06:42:34.160Z',
            parent_id: null,
          },
          {
            id: 2,
            web_url: 'https://gitlab.example/groups/group1/group2',
            name: 'group2',
            path: 'group1/group2',
            description: 'Group2',
            visibility: 'internal',
            share_with_group_lock: false,
            require_two_factor_authentication: false,
            two_factor_grace_period: 48,
            project_creation_level: 'developer',
            auto_devops_enabled: null,
            subgroup_creation_level: 'owner',
            emails_disabled: null,
            mentions_disabled: null,
            lfs_enabled: true,
            request_access_enabled: false,
            full_name: 'group2',
            full_path: 'group1/group2',
            created_at: '2017-12-07T13:20:40.675Z',
            parent_id: null,
          },
        ];
        return res(ctx.json(response));
      }),
      graphql
        .link('https://test-gitlab/api/graphql')
        .operation(async (req, res, ctx) =>
          res(
            ctx.data({
              group: {
                groupMembers: {
                  nodes:
                    req.variables.group === 'group1/group2'
                      ? [{ user: { id: 'gid://gitlab/User/1' } }]
                      : [],
                  pageInfo: {
                    endCursor: 'end',
                    hasNextPage: false,
                  },
                },
              },
            }),
          ),
        ),
    );

    await provider.connect(entityProviderConnection);

    const taskDef = schedule.getTasks()[0];
    expect(taskDef.id).toEqual(
      'GitlabOrgDiscoveryEntityProvider:test-id:refresh',
    );
    await (taskDef.fn as () => Promise<void>)();

    const expectedEntities = [
      {
        entity: {
          apiVersion: 'backstage.io/v1alpha1',
          kind: 'User',
          metadata: {
            annotations: {
              'backstage.io/managed-by-location':
                'url:https://test-gitlab/test1',
              'backstage.io/managed-by-origin-location':
                'url:https://test-gitlab/test1',
              'test-gitlab/user-login': 'https://gitlab.example/test1',
            },
            name: 'test1',
          },
          spec: {
            memberOf: ['group1-group2'],
            profile: {
              displayName: 'Test Testit',
              email: 'test@example.com',
              picture: 'https://secure.gravatar.com/',
            },
          },
        },
        locationKey: 'GitlabOrgDiscoveryEntityProvider:test-id',
      },
      {
        entity: {
          apiVersion: 'backstage.io/v1alpha1',
          kind: 'User',
          metadata: {
            annotations: {
              'backstage.io/managed-by-location':
                'url:https://test-gitlab/test2',
              'backstage.io/managed-by-origin-location':
                'url:https://test-gitlab/test2',
              'test-gitlab/user-login': 'https://gitlab.example/test2',
            },
            name: 'test2',
          },
          spec: {
            memberOf: [],
            profile: {
              displayName: undefined,
              email: 'test@example.com',
              picture: undefined,
            },
          },
        },
        locationKey: 'GitlabOrgDiscoveryEntityProvider:test-id',
      },
      {
        entity: {
          apiVersion: 'backstage.io/v1alpha1',
          kind: 'Group',
          metadata: {
            annotations: {
              'backstage.io/managed-by-location':
                'url:https://test-gitlab/group1/group2',
              'backstage.io/managed-by-origin-location':
                'url:https://test-gitlab/group1/group2',
              'test-gitlab/team-path': 'group1/group2',
            },
            description: 'Group2',
            name: 'group1-group2',
          },
          spec: {
            children: [],
            profile: {
              displayName: 'group2',
            },
            type: 'team',
          },
        },
        locationKey: 'GitlabOrgDiscoveryEntityProvider:test-id',
      },
    ];

    expect(entityProviderConnection.applyMutation).toHaveBeenCalledTimes(1);
    expect(entityProviderConnection.applyMutation).toHaveBeenCalledWith({
      type: 'full',
      entities: expectedEntities,
    });
  });

  it('apply full update on scheduled execution for gitlab.com', async () => {
    const config = new ConfigReader({
      integrations: {
        gitlab: [
          {
            host: 'gitlab.com',
            apiBaseUrl: 'https://gitlab.com/api/v4',
            token: '1234',
          },
        ],
      },
      catalog: {
        providers: {
          gitlab: {
            'test-id': {
              host: 'gitlab.com',
              group: 'group1',
              orgEnabled: true,
            },
          },
        },
      },
    });
    const schedule = new PersistingTaskRunner();
    const entityProviderConnection: EntityProviderConnection = {
      applyMutation: jest.fn(),
      refresh: jest.fn(),
    };
    const provider = GitlabOrgDiscoveryEntityProvider.fromConfig(config, {
      logger,
      schedule,
    })[0];
    expect(provider.getProviderName()).toEqual(
      'GitlabOrgDiscoveryEntityProvider:test-id',
    );

    server.use(
      graphql
        .link('https://gitlab.com/api/graphql')
        .query('listDescendantGroups', async (_, res, ctx) =>
          res(
            ctx.data({
              group: {
                descendantGroups: {
                  nodes: [
                    {
                      id: 'gid://gitlab/Group/456',
                      name: 'group2',
                      description: 'Group2',
                      fullPath: 'group1/group2',
                      parent: {
                        id: 'gid://gitlab/Group/123',
                      },
                    },
                    {
                      id: 'gid://gitlab/Group/789',
                      name: 'group3',
                      description: 'Group3',
                      fullPath: 'group1/group3',
                      parent: {
                        id: 'gid://gitlab/Group/123',
                      },
                    },
                  ],
                  pageInfo: {
                    endCursor: 'end',
                    hasNextPage: false,
                  },
                },
              },
            }),
          ),
        ),
      graphql
        .link('https://gitlab.com/api/graphql')
        .query('getGroupMembers', async (req, res, ctx) =>
          res(
            ctx.data({
              group: {
                groupMembers: {
                  nodes:
                    req.variables.group === 'group1/group2'
                      ? [{ user: { id: 'gid://gitlab/User/12' } }]
                      : [{ user: { id: 'gid://gitlab/User/34' } }],
                  pageInfo: {
                    endCursor: 'end',
                    hasNextPage: false,
                  },
                },
              },
            }),
          ),
        ),
      rest.get(
        `https://gitlab.com/api/v4/groups/group1/members/all`,
        (_req, res, ctx) => {
          const response = [
            {
              access_level: 30,
              created_at: '2023-07-17T08:58:34.984Z',
              expires_at: null,
              id: 12,
              username: 'testuser1',
              name: 'Test User 1',
              state: 'active',
              avatar_url: 'https://secure.gravatar.com/',
              web_url: 'https://gitlab.com/testuser1',
              email: 'testuser1@example.com',
              group_saml_identity: {
                provider: 'group_saml',
                extern_uid: '51',
                saml_provider_id: 1,
              },
              is_using_seat: true,
              membership_state: 'active',
            },
            {
              access_level: 30,
              created_at: '2023-07-19T08:58:34.984Z',
              expires_at: null,
              id: 34,
              username: 'testuser2',
              name: 'Test User 2',
              state: 'active',
              avatar_url: 'https://secure.gravatar.com/',
              web_url: 'https://gitlab.com/testuser2',
              email: 'testuser2@example.com',
              group_saml_identity: {
                provider: 'group_saml',
                extern_uid: '52',
                saml_provider_id: 1,
              },
              is_using_seat: true,
              membership_state: 'active',
            },
            {
              access_level: 50,
              created_at: '2023-07-15T08:58:34.984Z',
              expires_at: '2023-10-26',
              id: 54,
              username: 'group_100_bot_23dc8057bef66e05181f39be4652577c',
              name: 'Token Bot',
              state: 'active',
              avatar_url: 'https://secure.gravatar.com/',
              web_url:
                'https://gitlab.com/group_100_bot_23dc8057bef66e05181f39be4652577c',
              group_saml_identity: null,
              is_using_seat: false,
              membership_state: 'active',
            },
          ];
          return res(ctx.json(response));
        },
      ),
    );

    await provider.connect(entityProviderConnection);

    const taskDef = schedule.getTasks()[0];
    expect(taskDef.id).toEqual(
      'GitlabOrgDiscoveryEntityProvider:test-id:refresh',
    );
    await (taskDef.fn as () => Promise<void>)();

    const expectedEntities = [
      {
        entity: {
          apiVersion: 'backstage.io/v1alpha1',
          kind: 'User',
          metadata: {
            annotations: {
              'backstage.io/managed-by-location':
                'url:https://gitlab.com/testuser1',
              'backstage.io/managed-by-origin-location':
                'url:https://gitlab.com/testuser1',
              'gitlab.com/user-login': 'https://gitlab.com/testuser1',
              'gitlab.com/saml-external-uid': '51',
            },
            name: 'testuser1',
          },
          spec: {
            memberOf: ['group2'],
            profile: {
              displayName: 'Test User 1',
              email: 'testuser1@example.com',
              picture: 'https://secure.gravatar.com/',
            },
          },
        },
        locationKey: 'GitlabOrgDiscoveryEntityProvider:test-id',
      },
      {
        entity: {
          apiVersion: 'backstage.io/v1alpha1',
          kind: 'User',
          metadata: {
            annotations: {
              'backstage.io/managed-by-location':
                'url:https://gitlab.com/testuser2',
              'backstage.io/managed-by-origin-location':
                'url:https://gitlab.com/testuser2',
              'gitlab.com/user-login': 'https://gitlab.com/testuser2',
              'gitlab.com/saml-external-uid': '52',
            },
            name: 'testuser2',
          },
          spec: {
            memberOf: ['group3'],
            profile: {
              displayName: 'Test User 2',
              email: 'testuser2@example.com',
              picture: 'https://secure.gravatar.com/',
            },
          },
        },
        locationKey: 'GitlabOrgDiscoveryEntityProvider:test-id',
      },
      {
        entity: {
          apiVersion: 'backstage.io/v1alpha1',
          kind: 'Group',
          metadata: {
            annotations: {
              'backstage.io/managed-by-location':
                'url:https://gitlab.com/group1/group2',
              'backstage.io/managed-by-origin-location':
                'url:https://gitlab.com/group1/group2',
              'gitlab.com/team-path': 'group1/group2',
            },
            description: 'Group2',
            name: 'group2',
          },
          spec: {
            children: [],
            profile: {
              displayName: 'group2',
            },
            type: 'team',
          },
        },
        locationKey: 'GitlabOrgDiscoveryEntityProvider:test-id',
      },
      {
        entity: {
          apiVersion: 'backstage.io/v1alpha1',
          kind: 'Group',
          metadata: {
            annotations: {
              'backstage.io/managed-by-location':
                'url:https://gitlab.com/group1/group3',
              'backstage.io/managed-by-origin-location':
                'url:https://gitlab.com/group1/group3',
              'gitlab.com/team-path': 'group1/group3',
            },
            description: 'Group3',
            name: 'group3',
          },
          spec: {
            children: [],
            profile: {
              displayName: 'group3',
            },
            type: 'team',
          },
        },
        locationKey: 'GitlabOrgDiscoveryEntityProvider:test-id',
      },
    ];

    expect(entityProviderConnection.applyMutation).toHaveBeenCalledTimes(1);
    expect(entityProviderConnection.applyMutation).toHaveBeenCalledWith({
      type: 'full',
      entities: expectedEntities,
    });
  });

  it('fail without schedule and scheduler', () => {
    const config = new ConfigReader({
      integrations: {
        gitlab: [
          {
            host: 'test-gitlab',
            apiBaseUrl: 'https://api.gitlab.example/api/v4',
            token: '1234',
          },
        ],
      },
      catalog: {
        providers: {
          gitlab: {
            'test-id': {
              host: 'test-gitlab',
              group: 'test-group',
              orgEnabled: true,
            },
          },
        },
      },
    });

    expect(() =>
      GitlabOrgDiscoveryEntityProvider.fromConfig(config, {
        logger,
      }),
    ).toThrow('Either schedule or scheduler must be provided');
  });

  it('fail with scheduler but no schedule config', () => {
    const scheduler = {
      createScheduledTaskRunner: (_: any) => jest.fn(),
    } as unknown as PluginTaskScheduler;
    const config = new ConfigReader({
      integrations: {
        gitlab: [
          {
            host: 'test-gitlab',
            apiBaseUrl: 'https://api.gitlab.example/api/v4',
            token: '1234',
          },
        ],
      },
      catalog: {
        providers: {
          gitlab: {
            'test-id': {
              host: 'test-gitlab',
              group: 'test-group',
              orgEnabled: true,
            },
          },
        },
      },
    });

    expect(() =>
      GitlabOrgDiscoveryEntityProvider.fromConfig(config, {
        logger,
        scheduler,
      }),
    ).toThrow(
      'No schedule provided neither via code nor config for GitlabOrgDiscoveryEntityProvider:test-id',
    );
  });

  it('fail with scheduler but no group config when host is gitlab.com', () => {
    const scheduler = {
      createScheduledTaskRunner: (_: any) => jest.fn(),
    } as unknown as PluginTaskScheduler;
    const config = new ConfigReader({
      integrations: {
        gitlab: [
          {
            host: 'gitlab.com',
            apiBaseUrl: 'https://gitlab.com/api/v4',
            token: '1234',
          },
        ],
      },
      catalog: {
        providers: {
          gitlab: {
            'test-id': {
              host: 'gitlab.com',
              orgEnabled: true,
            },
          },
        },
      },
    });

    expect(() =>
      GitlabOrgDiscoveryEntityProvider.fromConfig(config, {
        logger,
        scheduler,
      }),
    ).toThrow(
      `Missing 'group' value for GitlabOrgDiscoveryEntityProvider:test-id`,
    );
  });

  it('single simple provider config with schedule in config', async () => {
    const schedule = new PersistingTaskRunner();
    const scheduler = {
      createScheduledTaskRunner: (_: any) => schedule,
    } as unknown as PluginTaskScheduler;
    const config = new ConfigReader({
      integrations: {
        gitlab: [
          {
            host: 'test-gitlab',
            apiBaseUrl: 'https://api.gitlab.example/api/v4',
            token: '1234',
          },
        ],
      },
      catalog: {
        providers: {
          gitlab: {
            'test-id': {
              host: 'test-gitlab',
              group: 'test-group',
              orgEnabled: true,
              schedule: {
                frequency: 'PT30M',
                timeout: 'PT3M',
              },
            },
          },
        },
      },
    });
    const providers = GitlabOrgDiscoveryEntityProvider.fromConfig(config, {
      logger,
      scheduler,
    });

    expect(providers).toHaveLength(1);
    expect(providers[0].getProviderName()).toEqual(
      'GitlabOrgDiscoveryEntityProvider:test-id',
    );
  });
});

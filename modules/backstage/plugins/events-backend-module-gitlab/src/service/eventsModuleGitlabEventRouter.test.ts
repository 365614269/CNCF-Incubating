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

import { startTestBackend } from '@backstage/backend-test-utils';
import { eventsExtensionPoint } from '@backstage/plugin-events-node/alpha';
import { eventsModuleGitlabEventRouter } from './eventsModuleGitlabEventRouter';
import { GitlabEventRouter } from '../router/GitlabEventRouter';

describe('eventsModuleGitlabEventRouter', () => {
  it('should be correctly wired and set up', async () => {
    let addedPublisher: GitlabEventRouter | undefined;
    let addedSubscriber: GitlabEventRouter | undefined;
    const extensionPoint = {
      addPublishers: (publisher: any) => {
        addedPublisher = publisher;
      },
      addSubscribers: (subscriber: any) => {
        addedSubscriber = subscriber;
      },
    };

    await startTestBackend({
      extensionPoints: [[eventsExtensionPoint, extensionPoint]],
      services: [],
      features: [eventsModuleGitlabEventRouter()],
    });

    expect(addedPublisher).not.toBeUndefined();
    expect(addedPublisher).toBeInstanceOf(GitlabEventRouter);
    expect(addedSubscriber).not.toBeUndefined();
    expect(addedSubscriber).toBeInstanceOf(GitlabEventRouter);
  });
});

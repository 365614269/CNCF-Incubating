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

import { getVoidLogger } from '@backstage/backend-common';
import { createWaitAction } from './wait';
import { Writable } from 'stream';
import { createMockDirectory } from '@backstage/backend-test-utils';

describe('debug:wait', () => {
  const action = createWaitAction();

  const logStream = {
    write: jest.fn(),
  } as jest.Mocked<Partial<Writable>> as jest.Mocked<Writable>;

  const mockDir = createMockDirectory();
  const workspacePath = mockDir.resolve('workspace');

  const mockContext = {
    input: {},
    baseUrl: 'somebase',
    workspacePath,
    logger: getVoidLogger(),
    logStream,
    output: jest.fn(),
    createTemporaryDirectory: jest.fn(),
  };

  beforeEach(() => {
    jest.resetAllMocks();
  });

  it('should wait for specified period of time', async () => {
    const context = {
      ...mockContext,
      input: {
        milliseconds: 50,
      },
    };
    const start = new Date().getTime();
    await action.handler(context);
    const end = new Date().getTime();
    expect(end - start).toBeGreaterThanOrEqual(50);
  });

  it('should not allow to set waiting time longer than the max waiting time', async () => {
    const context = {
      ...mockContext,
      input: {
        minutes: 11,
      },
    };

    await expect(async () => {
      await action.handler(context);
    }).rejects.toThrow(
      'Waiting duration is longer than the maximum threshold of 0 hours, 0 minutes, 30 seconds',
    );
  });
});

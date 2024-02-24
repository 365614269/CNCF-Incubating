/*
 * Copyright 2024 The Backstage Authors
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
import { mockServices } from '@backstage/backend-test-utils';
import { createLegacyAuthAdapters } from './createLegacyAuthAdapters';

describe('createLegacyAuthAdapters', () => {
  it('should pass through auth if only auth is provided', () => {
    const auth = {};
    const ret = createLegacyAuthAdapters({
      auth: auth as any,
      tokenManager: mockServices.tokenManager(),
      discovery: {} as any,
      identity: mockServices.identity(),
    });

    expect(ret.auth).toBe(auth);
  });

  it('should pass through httpAuth if only httpAuth is provided', () => {
    const httpAuth = {};
    const ret = createLegacyAuthAdapters({
      httpAuth: httpAuth as any,
      tokenManager: mockServices.tokenManager(),
      discovery: {} as any,
      identity: mockServices.identity(),
    });

    expect(ret.httpAuth).toBe(httpAuth);
  });

  it('should pass through both auth and httpAuth if both are provided', () => {
    const auth = {};
    const httpAuth = {};
    const ret = createLegacyAuthAdapters({
      auth: auth as any,
      httpAuth: httpAuth as any,
      tokenManager: mockServices.tokenManager(),
      discovery: {} as any,
      identity: mockServices.identity(),
    });

    expect(ret.auth).toBe(auth);
    expect(ret.httpAuth).toBe(httpAuth);
  });

  it('should adapt both auth and httpAuth if neither are provided', () => {
    const ret = createLegacyAuthAdapters({
      auth: undefined,
      httpAuth: undefined,
      tokenManager: mockServices.tokenManager(),
      discovery: {} as any,
      identity: mockServices.identity(),
    });

    expect(ret).toEqual({
      auth: expect.any(Object),
      httpAuth: expect.any(Object),
    });
  });
});

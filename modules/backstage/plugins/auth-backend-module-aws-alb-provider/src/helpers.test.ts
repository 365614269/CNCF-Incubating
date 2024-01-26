import NodeCache from 'node-cache';
import { makeProfileInfo, provisionKeyCache } from './helpers';
import * as crypto from 'crypto';
import { JWTHeaderParameters } from 'jose';
import { PassportProfile } from '@backstage/plugin-auth-node';
import jwtDecoder from 'jwt-decode';

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

const mockKey = async () => {
  return `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnuN4LlaJhaUpx+qZFTzYCrSBLk0I
yOlxJ2VW88mLAQGJ7HPAvOdylxZsItMnzCuqNzZvie8m/NJsOjhDncVkrw==
-----END PUBLIC KEY-----
`;
};
jest.mock('crypto');
const cryptoMock = crypto as jest.Mocked<any>;
jest.mock('node-fetch', () => ({
  __esModule: true,
  default: async () => {
    return {
      text: async () => {
        return mockKey();
      },
    };
  },
}));

const jwtMock = jwtDecoder as jest.Mocked<any>;
jest.mock('jwt-decode');

describe('helpers', () => {
  const nodeCache = jest.fn() as unknown as NodeCache;
  nodeCache.set = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });
  it('should create a key', () => {
    const getKey = provisionKeyCache('eu-west-1', nodeCache);
    expect(getKey).toBeDefined();
  });
  it('should return a key from cache', async () => {
    const getKey = provisionKeyCache('eu-west-1', nodeCache);

    cryptoMock.createPublicKey.mockReturnValueOnce('key');
    nodeCache.get = jest.fn().mockReturnValue('key');

    const key = await getKey({ kid: 'kid' } as unknown as JWTHeaderParameters);

    expect(key).toBe('key');
  });
  it('should update cache if key is not found', async () => {
    const getKey = provisionKeyCache('eu-west-1', nodeCache);

    nodeCache.get = jest.fn().mockReturnValue(undefined);
    jest.spyOn(nodeCache, 'set');
    cryptoMock.createPublicKey.mockReturnValue({
      export: jest.fn().mockReturnValue('key'),
    });

    await getKey({ kid: 'kid' } as unknown as JWTHeaderParameters);
    expect(nodeCache.set).toHaveBeenCalledWith('kid', 'key');
  });
  it('should throw error if key is not found', async () => {
    const getKey = provisionKeyCache('eu-west-1', nodeCache);

    nodeCache.get = jest.fn().mockReturnValue(undefined);
    cryptoMock.createPublicKey.mockReturnValue(undefined);

    await expect(
      getKey({ kid: 'kid' } as unknown as JWTHeaderParameters),
    ).rejects.toThrow();
  });
  it('should throw if key is not present in request header', async () => {
    const getKey = provisionKeyCache('eu-west-1', nodeCache);

    nodeCache.get = jest.fn().mockReturnValue(undefined);

    await expect(getKey({} as unknown as JWTHeaderParameters)).rejects.toThrow(
      'No key id was specified in header',
    );
  });
});

describe('makeProfileInfo', () => {
  it('should return profile info', () => {
    const profile = {
      id: 'id',
      displayName: 'displayName',
      username: 'username',
      name: {
        familyName: 'familyName',
        givenName: 'givenName',
      },
      emails: [{ value: 'email' }],
      photos: [{ value: 'picture' }],
    } as PassportProfile;
    const accessToken = 'accessToken';
    const result = {
      email: 'email',
      picture: 'picture',
      displayName: 'displayName',
    };
    expect(makeProfileInfo(profile, accessToken)).toEqual(result);
  });
  it('should return profile info from id token', () => {
    jwtMock.mockReturnValueOnce({
      email: 'email',
      picture: 'picture',
      name: 'displayName',
    });
    const profile = {
      name: {
        familyName: 'familyName',
        givenName: 'givenName',
      },
    } as PassportProfile;
    const idToken = 'idToken';
    const result = {
      email: 'email',
      picture: 'picture',
      displayName: 'displayName',
    };
    expect(makeProfileInfo(profile, idToken)).toEqual(result);
  });
});

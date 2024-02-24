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

import { ServerTokenManager, TokenManager } from '@backstage/backend-common';
import {
  AuthService,
  BackstageCredentials,
  BackstagePrincipalTypes,
  BackstageServicePrincipal,
  BackstageNonePrincipal,
  BackstageUserPrincipal,
  IdentityService,
  coreServices,
  createServiceFactory,
} from '@backstage/backend-plugin-api';
import { AuthenticationError } from '@backstage/errors';
import {
  DefaultIdentityClient,
  IdentityApiGetIdentityRequest,
} from '@backstage/plugin-auth-node';
import { decodeJwt } from 'jose';

/** @internal */
export type InternalBackstageCredentials<TPrincipal = unknown> =
  BackstageCredentials<TPrincipal> & {
    version: string;
    token?: string;
    authMethod: 'token' | 'cookie' | 'none';
  };

export function createCredentialsWithServicePrincipal(
  sub: string,
): InternalBackstageCredentials<BackstageServicePrincipal> {
  return {
    $$type: '@backstage/BackstageCredentials',
    version: 'v1',
    principal: {
      type: 'service',
      subject: sub,
    },
    authMethod: 'token',
  };
}

export function createCredentialsWithUserPrincipal(
  sub: string,
  token: string,
  authMethod: 'token' | 'cookie' = 'token',
): InternalBackstageCredentials<BackstageUserPrincipal> {
  return {
    $$type: '@backstage/BackstageCredentials',
    version: 'v1',
    token,
    principal: {
      type: 'user',
      userEntityRef: sub,
    },
    authMethod,
  };
}

export function createCredentialsWithNonePrincipal(): InternalBackstageCredentials<BackstageNonePrincipal> {
  return {
    $$type: '@backstage/BackstageCredentials',
    version: 'v1',
    principal: {
      type: 'none',
    },
    authMethod: 'none',
  };
}

export function toInternalBackstageCredentials(
  credentials: BackstageCredentials,
): InternalBackstageCredentials<
  BackstageUserPrincipal | BackstageServicePrincipal | BackstageNonePrincipal
> {
  if (credentials.$$type !== '@backstage/BackstageCredentials') {
    throw new Error('Invalid credential type');
  }

  const internalCredentials = credentials as InternalBackstageCredentials<
    BackstageUserPrincipal | BackstageServicePrincipal | BackstageNonePrincipal
  >;

  if (internalCredentials.version !== 'v1') {
    throw new Error(
      `Invalid credential version ${internalCredentials.version}`,
    );
  }

  return internalCredentials;
}

/** @internal */
class DefaultAuthService implements AuthService {
  constructor(
    private readonly tokenManager: TokenManager,
    private readonly identity: IdentityService,
    private readonly pluginId: string,
    private readonly disableDefaultAuthPolicy: boolean,
  ) {}

  async authenticate(token: string): Promise<BackstageCredentials> {
    const { sub, aud } = decodeJwt(token);

    // Legacy service-to-service token
    if (sub === 'backstage-server' && !aud) {
      await this.tokenManager.authenticate(token);
      return createCredentialsWithServicePrincipal('external:backstage-plugin');
    }

    // User Backstage token
    const identity = await this.identity.getIdentity({
      request: {
        headers: { authorization: `Bearer ${token}` },
      },
    } as IdentityApiGetIdentityRequest);

    if (!identity) {
      throw new AuthenticationError('Invalid user token');
    }

    return createCredentialsWithUserPrincipal(
      identity.identity.userEntityRef,
      token,
    );
  }

  isPrincipal<TType extends keyof BackstagePrincipalTypes>(
    credentials: BackstageCredentials,
    type: TType,
  ): credentials is BackstageCredentials<BackstagePrincipalTypes[TType]> {
    const principal = credentials.principal as
      | BackstageUserPrincipal
      | BackstageServicePrincipal;

    if (type === 'unknown') {
      return true;
    }

    if (principal.type !== type) {
      return false;
    }

    return true;
  }

  async getOwnServiceCredentials(): Promise<
    BackstageCredentials<BackstageServicePrincipal>
  > {
    return createCredentialsWithServicePrincipal(`plugin:${this.pluginId}`);
  }

  async getPluginRequestToken(options: {
    onBehalfOf: BackstageCredentials;
    targetPluginId: string;
  }): Promise<{ token: string }> {
    const internalForward = toInternalBackstageCredentials(options.onBehalfOf);
    const { type } = internalForward.principal;

    // Since disabling the default policy means we'll be allowing
    // unauthenticated requests through, we might have unauthenticated
    // credentials from service calls that reach this point. If that's the case,
    // we'll want to keep "forwarding" the unauthenticated credentials, which we
    // do by returning an empty token.
    if (type === 'none' && this.disableDefaultAuthPolicy) {
      return { token: '' };
    }

    switch (type) {
      // TODO: Check whether the principal is ourselves
      case 'service':
        return this.tokenManager.getToken();
      case 'user':
        if (!internalForward.token) {
          throw new Error('User credentials is unexpectedly missing token');
        }
        return { token: internalForward.token };
      default:
        throw new AuthenticationError(
          `Refused to issue service token for credential type '${type}'`,
        );
    }
  }
}

/** @public */
export const authServiceFactory = createServiceFactory({
  service: coreServices.auth,
  deps: {
    config: coreServices.rootConfig,
    logger: coreServices.rootLogger,
    discovery: coreServices.discovery,
    plugin: coreServices.pluginMetadata,
  },
  createRootContext({ config, logger }) {
    return ServerTokenManager.fromConfig(config, { logger });
  },
  async factory({ discovery, config, plugin }, tokenManager) {
    const identity = DefaultIdentityClient.create({ discovery });
    const disableDefaultAuthPolicy = Boolean(
      config.getOptionalBoolean(
        'backend.auth.dangerouslyDisableDefaultAuthPolicy',
      ),
    );
    return new DefaultAuthService(
      tokenManager,
      identity,
      plugin.getId(),
      disableDefaultAuthPolicy,
    );
  },
});

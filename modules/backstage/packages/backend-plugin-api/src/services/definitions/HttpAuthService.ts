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

import { Request, Response } from 'express';
import { BackstageCredentials, BackstagePrincipalTypes } from './AuthService';

/** @public */
export interface HttpAuthService {
  credentials<TAllowed extends keyof BackstagePrincipalTypes = 'unknown'>(
    req: Request<any, any, any, any, any>,
    options?: {
      allow?: Array<TAllowed>;
      allowedAuthMethods?: Array<'token' | 'cookie'>;
    },
  ): Promise<BackstageCredentials<BackstagePrincipalTypes[TAllowed]>>;

  issueUserCookie(res: Response): Promise<void>;
}

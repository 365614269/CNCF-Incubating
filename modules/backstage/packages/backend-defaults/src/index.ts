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

/**
 * Backend defaults used by Backstage backend apps
 *
 * @packageDocumentation
 */

// This import is here as a workaround for a cyclic dependency bug where
// backend-common must be loaded before backend-app-api
// TODO(Rugvip): Remove this once backend-common is no longer used by backend-app-api
import '@backstage/backend-common';

export type { CreateBackendOptions } from './CreateBackend';
export { createBackend } from './CreateBackend';

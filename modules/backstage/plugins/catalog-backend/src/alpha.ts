/*
 * Copyright 2023 The Backstage Authors
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

// TODO(Rugvip): Re-exported for alpha types as the API report will otherwise
//               produce warnings due to the indirect dependency. Would be nice to avoid.
import type { EntitiesSearchFilter } from './catalog/types';

export type { /** @alpha */ EntitiesSearchFilter };

export * from './permissions';
export { catalogPlugin } from './service/CatalogPlugin';

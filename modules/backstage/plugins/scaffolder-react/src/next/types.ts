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

import type { FormProps as SchemaFormProps } from '@rjsf/core-v5';

// TODO(Rugvip): The FormProps type is actually supposed to be alpha, but since we want to
//               refer to it from @backstage/plugin-scaffolder, it needs to be public for now.
//               Once we support internal alpha re-exports this should be switched to an alpha export.

/**
 * Any `@rjsf/core` form properties that are publicly exposed to the `NextScaffolderpage`
 *
 * @alpha
 */
export type FormProps = Pick<
  SchemaFormProps,
  'transformErrors' | 'noHtml5Validate'
>;

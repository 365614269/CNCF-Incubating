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
import React from 'react';
import { createDevApp } from '@backstage/dev-utils';
import { Playground } from './Playground';

import { createPlugin } from '@backstage/core-plugin-api';

/**
 * @deprecated Importing and including this plugin in an app has no effect.
 * This will be removed in a future release.
 *
 * @public
 */
export const analyticsModuleGA4 = createPlugin({
  id: 'analytics-provider-ga4',
});
createDevApp()
  .registerPlugin(analyticsModuleGA4)
  .addPage({
    path: '/ga4',
    title: 'GA4 Playground',
    element: <Playground />,
  })
  .render();

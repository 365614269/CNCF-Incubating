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

import { TemplateExample } from '@backstage/plugin-scaffolder-node';
import yaml from 'yaml';

export const examples: TemplateExample[] = [
  {
    description: 'Enables GitHub Pages for a repository.',
    example: yaml.stringify({
      steps: [
        {
          action: 'github:pages',
          id: 'github-pages',
          name: 'Enable GitHub Pages',
          input: {
            repoUrl: 'github.com?repo=repo&owner=owner',
            buildType: 'workflow',
            sourceBranch: 'main',
            sourcePath: '/',
            token: 'gph_YourGitHubToken',
          },
        },
      ],
    }),
  },
];

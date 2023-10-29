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

import { createExtension } from '@backstage/frontend-plugin-api';
import { resolveAppTree } from './resolveAppTree';

const extBaseConfig = {
  id: 'test',
  attachTo: { id: 'nonexistent', input: 'nonexistent' },
  output: {},
  factory: () => ({}),
};

const extension = createExtension(extBaseConfig);

const baseSpec = {
  extension,
  attachTo: { id: 'nonexistent', input: 'nonexistent' },
  disabled: false,
};

describe('buildAppTree', () => {
  it('should fail to create an empty tree', () => {
    expect(() => resolveAppTree('core', [])).toThrow(
      "No root node with id 'core' found in app tree",
    );
  });

  it('should create a tree with only one node', () => {
    const tree = resolveAppTree('core', [{ ...baseSpec, id: 'core' }]);
    expect(tree.root).toEqual({
      spec: { ...baseSpec, id: 'core' },
      edges: { attachments: new Map() },
    });
    expect(Array.from(tree.orphans)).toEqual([]);
    expect(Array.from(tree.nodes.keys())).toEqual(['core']);
  });

  it('should create a tree', () => {
    const tree = resolveAppTree('b', [
      { ...baseSpec, id: 'a' },
      { ...baseSpec, id: 'b' },
      { ...baseSpec, id: 'c' },
      { ...baseSpec, attachTo: { id: 'b', input: 'x' }, id: 'bx1' },
      { ...baseSpec, attachTo: { id: 'b', input: 'x' }, id: 'bx2' },
      { ...baseSpec, attachTo: { id: 'b', input: 'y' }, id: 'by1' },
      { ...baseSpec, attachTo: { id: 'd', input: 'x' }, id: 'dx1' },
    ]);

    expect(Array.from(tree.nodes.keys())).toEqual([
      'a',
      'b',
      'c',
      'bx1',
      'bx2',
      'by1',
      'dx1',
    ]);

    expect(JSON.parse(JSON.stringify(tree.root))).toMatchInlineSnapshot(`
      {
        "attachments": {
          "x": [
            {
              "id": "bx1",
            },
            {
              "id": "bx2",
            },
          ],
          "y": [
            {
              "id": "by1",
            },
          ],
        },
        "id": "b",
      }
    `);
    expect(String(tree.root)).toMatchInlineSnapshot(`
      "<b>
        x [
          <bx1 />
          <bx2 />
        ]
        y [
          <by1 />
        ]
      </b>"
    `);

    const orphans = Array.from(tree.orphans).map(String);
    expect(orphans).toMatchInlineSnapshot(`
      [
        "<a />",
        "<c />",
        "<dx1 />",
      ]
    `);
  });

  it('should create a tree out of order', () => {
    const tree = resolveAppTree('b', [
      { ...baseSpec, attachTo: { id: 'b', input: 'x' }, id: 'bx2' },
      { ...baseSpec, id: 'a' },
      { ...baseSpec, attachTo: { id: 'b', input: 'y' }, id: 'by1' },
      { ...baseSpec, id: 'b' },
      { ...baseSpec, attachTo: { id: 'b', input: 'x' }, id: 'bx1' },
      { ...baseSpec, id: 'c' },
      { ...baseSpec, attachTo: { id: 'd', input: 'x' }, id: 'dx1' },
    ]);

    expect(Array.from(tree.nodes.keys())).toEqual([
      'bx2',
      'a',
      'by1',
      'b',
      'bx1',
      'c',
      'dx1',
    ]);

    expect(String(tree.root)).toMatchInlineSnapshot(`
      "<b>
        x [
          <bx2 />
          <bx1 />
        ]
        y [
          <by1 />
        ]
      </b>"
    `);

    const orphans = Array.from(tree.orphans).map(String);
    expect(orphans).toMatchInlineSnapshot(`
      [
        "<a />",
        "<c />",
        "<dx1 />",
      ]
    `);
  });

  it('throws an error when duplicated extensions are detected', () => {
    expect(() =>
      resolveAppTree('core', [
        { ...baseSpec, id: 'a' },
        { ...baseSpec, id: 'a' },
      ]),
    ).toThrow("Unexpected duplicate extension id 'a'");
  });
});

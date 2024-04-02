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

import { ConfigReader } from '@backstage/config';
import { JsonObject } from '@backstage/types';
import { getVoidLogger } from '../logging';
import { DefaultReadTreeResponseFactory } from './tree';
import { AwsCodeCommitUrlReader, parseUrl } from './AwsCodeCommitUrlReader';
import { UrlReaderPredicateTuple } from './types';
import path from 'path';
import { NotModifiedError } from '@backstage/errors';
import { mockClient } from 'aws-sdk-client-mock';
import {
  CodeCommitClient,
  GetFileCommand,
  GetFolderCommand,
} from '@aws-sdk/client-codecommit';
import fs from 'fs';
import { DefaultAwsCredentialsManager } from '@backstage/integration-aws-node';
import {
  AwsCodeCommitIntegration,
  readAwsCodeCommitIntegrationConfig,
} from '@backstage/integration';

const AMAZON_AWS_CODECOMMIT_HOST = 'console.aws.amazon.com';

const treeResponseFactory = DefaultReadTreeResponseFactory.create({
  config: new ConfigReader({}),
});

describe('parseUrl', () => {
  it('supports all formats (requireGitPath = true)', () => {
    expect(
      parseUrl(
        'https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-repo/browse/--/catalog-info.yaml?region=eu-west-1',
        true,
      ),
    ).toEqual({
      path: 'catalog-info.yaml',
      repositoryName: 'my-repo',
      region: 'eu-west-1',
    });
    expect(
      parseUrl(
        'https://us-east-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-repo2/browse/--/test1/test2/catalog-info.yaml',
        true,
      ),
    ).toEqual({
      path: 'test1/test2/catalog-info.yaml',
      repositoryName: 'my-repo2',
      region: 'us-east-1',
    });
    expect(
      parseUrl(
        'https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-test-repo/browse/refs/heads/develop/--/some-path/catalog-info.yaml',
        true,
      ),
    ).toEqual({
      path: 'some-path/catalog-info.yaml',
      repositoryName: 'my-test-repo',
      region: 'eu-west-1',
      commitSpecifier: 'refs/heads/develop',
    });
    expect(
      parseUrl(
        'https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-test-repo/browse/refs/tags/v1.0/--/some-path/catalog-info.yaml',
        true,
      ),
    ).toEqual({
      path: 'some-path/catalog-info.yaml',
      repositoryName: 'my-test-repo',
      region: 'eu-west-1',
      commitSpecifier: 'refs/tags/v1.0',
    });
    expect(
      parseUrl(
        'https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-test-repo/browse/c1234/--/some-path/catalog-info.yaml',
        true,
      ),
    ).toEqual({
      path: 'some-path/catalog-info.yaml',
      repositoryName: 'my-test-repo',
      region: 'eu-west-1',
      commitSpecifier: 'c1234',
    });
  });
  it('throw correct error when not providing full url to file (requireGitPath = true)', () => {
    expect(() =>
      parseUrl(
        `https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-repo`,
        true,
      ),
    ).toThrow('Please provide full path to yaml file from CodeCommit');
  });
  it('supports all formats (requireGitPath = false)', () => {
    expect(
      parseUrl(
        'https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-test-techdocs',
      ),
    ).toEqual({
      path: '/',
      repositoryName: 'my-test-techdocs',
      region: 'eu-west-1',
    });
    expect(
      parseUrl(
        'https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-test-techdocs/',
      ),
    ).toEqual({
      path: '/',
      repositoryName: 'my-test-techdocs',
      region: 'eu-west-1',
    });
    expect(
      parseUrl(
        'https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-test-techdocs/browse?region=eu-west-1',
      ),
    ).toEqual({
      path: '/',
      repositoryName: 'my-test-techdocs',
      region: 'eu-west-1',
    });
    expect(
      parseUrl(
        'https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-test-techdocs/browse/refs/heads/develop',
      ),
    ).toEqual({
      path: '/',
      repositoryName: 'my-test-techdocs',
      region: 'eu-west-1',
      commitSpecifier: 'refs/heads/develop',
    });
    expect(
      parseUrl(
        'https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-test-techdocs/browse/refs/tags/v1.0',
      ),
    ).toEqual({
      path: '/',
      repositoryName: 'my-test-techdocs',
      region: 'eu-west-1',
      commitSpecifier: 'refs/tags/v1.0',
    });
    expect(
      parseUrl(
        'https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-test-techdocs/browse/c1234',
      ),
    ).toEqual({
      path: '/',
      repositoryName: 'my-test-techdocs',
      region: 'eu-west-1',
      commitSpecifier: 'c1234',
    });
    expect(
      parseUrl(
        'https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-test-techdocs/browse/c1234/',
      ),
    ).toEqual({
      path: '/',
      repositoryName: 'my-test-techdocs',
      region: 'eu-west-1',
      commitSpecifier: 'c1234',
    });
    expect(
      parseUrl(
        'https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-test-techdocs/browse/c1234/--/folder/',
      ),
    ).toEqual({
      path: 'folder/',
      repositoryName: 'my-test-techdocs',
      region: 'eu-west-1',
      commitSpecifier: 'c1234',
    });
  });

  it('throw correct error when providing edit url', () => {
    expect(() =>
      parseUrl(
        `https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-repo/files/edit/refs/heads/develop/--/test/catalog-info.yaml`,
      ),
    ).toThrow(
      'Please provide the view url to yaml file from CodeCommit, not the edit url',
    );
  });
});

describe('AwsCodeCommitUrlReader', () => {
  const codeCommitClient = mockClient(CodeCommitClient);

  const createReader = (config: JsonObject): UrlReaderPredicateTuple[] => {
    return AwsCodeCommitUrlReader.factory({
      config: new ConfigReader(config),
      logger: getVoidLogger(),
      treeResponseFactory,
    });
  };

  it('creates a sample reader without the awsCodeCommit field', () => {
    const entries = createReader({
      integrations: {},
    });

    expect(entries).toHaveLength(1);
  });

  it('creates a reader with credentials correctly configured', () => {
    const awsCodeCommitIntegrations = [];
    awsCodeCommitIntegrations.push({
      host: AMAZON_AWS_CODECOMMIT_HOST,
      accessKeyId: 'fakekey',
      secretAccessKey: 'fakekey',
    });

    const entries = createReader({
      integrations: {
        awsCodeCommit: awsCodeCommitIntegrations,
      },
    });

    expect(entries).toHaveLength(1);
  });

  it('creates a reader with default credentials provider', () => {
    const awsCodeCommitIntegrations = [];
    awsCodeCommitIntegrations.push({
      host: AMAZON_AWS_CODECOMMIT_HOST,
    });

    const entries = createReader({
      integrations: {
        awsCodeCommit: awsCodeCommitIntegrations,
      },
    });

    expect(entries).toHaveLength(1);
  });

  describe('predicates', () => {
    const readers = createReader({
      integrations: {
        awsCodeCommit: [{}],
      },
    });
    const predicate = readers[0].predicate;

    it('returns true for the correct aws CodeCommit storage host', () => {
      expect(
        predicate(
          new URL(
            'https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-repo',
          ),
        ),
      ).toBe(true);
    });

    it('returns true for a url with the full path and the correct host', () => {
      expect(
        predicate(
          new URL(
            'https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-repo/browse/--/catalog-info.yaml?region=eu-west-1',
          ),
        ),
      ).toBe(true);
    });

    it('returns false for an incorrect host', () => {
      expect(predicate(new URL('https://amazon.com'))).toBe(false);
    });

    it('returns false for a completely different host', () => {
      expect(predicate(new URL('https://storage.cloud.google.com'))).toBe(
        false,
      );
    });

    it('returns false for a path that starts with the wrong format', () => {
      expect(
        predicate(
          new URL(
            'https://s3.console.aws.amazon.com/s3/object/bucket?&bucketType=general&prefix=catalog-info.yaml',
          ),
        ),
      ).toBe(false);
    });
  });

  describe('read', () => {
    const [{ reader }] = createReader({
      integrations: {
        awsCodeCommit: [
          {
            host: 'amazonaws.com',
            accessKeyId: 'fake-access-key',
            secretAccessKey: 'fake-secret-key',
          },
        ],
      },
    });

    beforeEach(() => {
      codeCommitClient.reset();

      codeCommitClient.on(GetFileCommand).resolves({
        fileContent: fs.readFileSync(
          path.resolve(
            __dirname,
            '__fixtures__/awsCodeCommit/awsCodeCommit-mock-object.yaml',
          ),
        ),
      });
    });

    it('returns contents of a file in a repository', async () => {
      const { buffer } = await reader.readUrl(
        'https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-repo/browse/--/catalog-info.yaml',
      );
      const response = await buffer();
      expect(response.toString().trim()).toBe('site_name: Test');
    });

    it('rejects unknown targets', async () => {
      const url =
        'https://eu-west-1.console.aws.NOTamazon.com/codesuite/codecommit/repositories/my-repo/browse/--/catalog-info.yaml';
      const expectedSnapshot = `[Error: Could not retrieve file from CodeCommit; caused by Error: Invalid AWS CodeCommit URL (unexpected host format): ${url}]`;
      await expect(reader.readUrl(url)).rejects.toMatchInlineSnapshot(
        expectedSnapshot,
      );
    });
  });

  describe('readUrl', () => {
    const [{ reader }] = createReader({
      integrations: {
        awsCodeCommit: [
          {
            host: AMAZON_AWS_CODECOMMIT_HOST,
            accessKeyId: 'fake-access-key',
            secretAccessKey: 'fake-secret-key',
          },
        ],
      },
    });

    beforeEach(() => {
      codeCommitClient.reset();

      codeCommitClient.on(GetFileCommand).resolves({
        fileContent: fs.readFileSync(
          path.resolve(
            __dirname,
            '__fixtures__/awsCodeCommit/awsCodeCommit-mock-object.yaml',
          ),
        ),
        commitId: `123abc`,
      });
    });

    it('returns contents of a file in a repository via buffer', async () => {
      const { buffer, etag } = await reader.readUrl(
        'https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-repo/browse/--/catalog-info.yaml',
      );
      expect(etag).toBe('123abc');
      const response = await buffer();
      expect(response.toString().trim()).toBe('site_name: Test');
    });

    it('returns contents of a file in a repository via stream', async () => {
      const { buffer, etag } = await reader.readUrl(
        'https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-repo/browse/--/catalog-info.yaml',
      );
      expect(etag).toBe('123abc');
      const response = await buffer();
      expect(response.toString().trim()).toBe('site_name: Test');
    });

    it('rejects unknown targets', async () => {
      const url =
        'https://eu-west-1.console.aws.NOTamazon.com/codesuite/codecommit/repositories/my-repo/browse/--/catalog-info.yaml';
      const expectedSnapshot = `[Error: Could not retrieve file from CodeCommit; caused by Error: Invalid AWS CodeCommit URL (unexpected host format): ${url}]`;
      await expect(reader.readUrl!(url)).rejects.toMatchInlineSnapshot(
        expectedSnapshot,
      );
    });
  });

  describe('readUrl with etag', () => {
    const [{ reader }] = createReader({
      integrations: {
        awsCodeCommit: [
          {
            host: AMAZON_AWS_CODECOMMIT_HOST,
            accessKeyId: 'fake-access-key',
            secretAccessKey: 'fake-secret-key',
          },
        ],
      },
    });

    beforeEach(() => {
      codeCommitClient.reset();

      codeCommitClient.on(GetFileCommand).resolves({
        fileContent: fs.readFileSync(
          path.resolve(
            __dirname,
            '__fixtures__/awsCodeCommit/awsCodeCommit-mock-object.yaml',
          ),
        ),
        commitId: `123abc`,
        blobId: '999',
        filePath: 'catalog.yaml',
        fileMode: 'EXECUTABLE',
        fileSize: 123,
      });
    });

    it('Throw NotModifiedError on matching eTag', async () => {
      await expect(
        reader.readUrl!(
          'https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-repo/browse/--/catalog-info.yaml',
          {
            etag: '123abc',
          },
        ),
      ).rejects.toThrow(NotModifiedError);
    });
  });

  describe('readTree', () => {
    let awsCodeCommitUrlReader: AwsCodeCommitUrlReader;

    beforeEach(() => {
      codeCommitClient.reset();

      codeCommitClient
        .on(GetFolderCommand, {
          folderPath: `/`,
          repositoryName: `my-test-techdocs`,
          commitSpecifier: undefined,
        })
        .resolves({
          files: [
            {
              absolutePath: `awsCodeCommit-mock-object.yaml`,
              relativePath: `awsCodeCommit-mock-object.yaml`,
            },
          ],
          subFolders: [
            {
              absolutePath: `subFolder`,
              relativePath: `subFolder`,
            },
          ],
        });
      codeCommitClient
        .on(GetFolderCommand, {
          folderPath: `subFolder`,
          repositoryName: `my-test-techdocs`,
          commitSpecifier: undefined,
        })
        .resolves({
          files: [
            {
              absolutePath: `subFolder/awsCodeCommit-mock-object2.yaml`,
              relativePath: `subFolder/awsCodeCommit-mock-object2.yaml`,
            },
          ],
        });

      codeCommitClient
        .on(GetFileCommand, {
          filePath: `awsCodeCommit-mock-object.yaml`,
          commitSpecifier: undefined,
          repositoryName: `my-test-techdocs`,
        })
        .resolves({
          fileContent: fs.readFileSync(
            path.resolve(
              __dirname,
              '__fixtures__/awsCodeCommit/awsCodeCommit-mock-object.yaml',
            ),
          ),
        });
      codeCommitClient
        .on(GetFileCommand, {
          filePath: `subFolder/awsCodeCommit-mock-object2.yaml`,
          commitSpecifier: undefined,
          repositoryName: `my-test-techdocs`,
        })
        .resolves({
          fileContent: fs.readFileSync(
            path.resolve(
              __dirname,
              '__fixtures__/awsCodeCommit/subFolder/awsCodeCommit-mock-object2.yaml',
            ),
          ),
        });

      const config = new ConfigReader({
        host: AMAZON_AWS_CODECOMMIT_HOST,
        accessKeyId: 'fake-access-key',
        secretAccessKey: 'fake-secret-key',
      });

      const credsManager = DefaultAwsCredentialsManager.fromConfig(config);

      awsCodeCommitUrlReader = new AwsCodeCommitUrlReader(
        credsManager,
        new AwsCodeCommitIntegration(
          readAwsCodeCommitIntegrationConfig(config),
        ),
        { treeResponseFactory },
      );
    });

    it('returns contents of a file in a repository', async () => {
      const response = await awsCodeCommitUrlReader.readTree(
        'https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/my-test-techdocs',
      );

      const files = await response.files();
      const bodyRootFile = await files[0].content();
      const bodySubfolderFile = await files[1].content();

      expect(files.length).toEqual(2);
      expect(bodyRootFile.toString().trim()).toBe('site_name: Test');
      expect(bodySubfolderFile.toString().trim()).toBe('site_name: Test2');
    });
  });
});

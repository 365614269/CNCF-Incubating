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
import { makeStyles } from '@material-ui/core';
import React, { useState } from 'react';
import type { LayoutOptions } from '@backstage/plugin-scaffolder-react';
import { NextFieldExtensionOptions } from '@backstage/plugin-scaffolder-react/alpha';
import { TemplateDirectoryAccess } from '../../lib/filesystem';
import { DirectoryEditorProvider } from '../../components/TemplateEditorPage/DirectoryEditorContext';
import { DryRunProvider } from '../../components/TemplateEditorPage/DryRunContext';
import { DryRunResults } from '../../components/TemplateEditorPage/DryRunResults';
import { TemplateEditorBrowser } from '../../components/TemplateEditorPage/TemplateEditorBrowser';
import { TemplateEditorForm } from './TemplateEditorForm';
import { TemplateEditorTextArea } from '../../components/TemplateEditorPage/TemplateEditorTextArea';

const useStyles = makeStyles({
  // Reset and fix sizing to make sure scrolling behaves correctly
  root: {
    gridArea: 'pageContent',

    display: 'grid',
    gridTemplateAreas: `
      "browser editor preview"
      "results results results"
    `,
    gridTemplateColumns: '1fr 3fr 2fr',
    gridTemplateRows: '1fr auto',
  },
  browser: {
    gridArea: 'browser',
    overflow: 'auto',
  },
  editor: {
    gridArea: 'editor',
    overflow: 'auto',
  },
  preview: {
    gridArea: 'preview',
    overflow: 'auto',
  },
  results: {
    gridArea: 'results',
  },
});

export const TemplateEditor = (props: {
  directory: TemplateDirectoryAccess;
  fieldExtensions?: NextFieldExtensionOptions<any, any>[];
  layouts?: LayoutOptions[];
  onClose?: () => void;
}) => {
  const classes = useStyles();

  const [errorText, setErrorText] = useState<string>();

  return (
    <DirectoryEditorProvider directory={props.directory}>
      <DryRunProvider>
        <main className={classes.root}>
          <section className={classes.browser}>
            <TemplateEditorBrowser onClose={props.onClose} />
          </section>
          <section className={classes.editor}>
            <TemplateEditorTextArea.DirectoryEditor errorText={errorText} />
          </section>
          <section className={classes.preview}>
            <TemplateEditorForm.DirectoryEditorDryRun
              setErrorText={setErrorText}
              fieldExtensions={props.fieldExtensions}
              layouts={props.layouts}
            />
          </section>
          <section className={classes.results}>
            <DryRunResults />
          </section>
        </main>
      </DryRunProvider>
    </DirectoryEditorProvider>
  );
};

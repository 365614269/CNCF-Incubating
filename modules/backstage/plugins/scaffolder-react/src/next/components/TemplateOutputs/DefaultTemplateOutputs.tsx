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
import { InfoCard, MarkdownContent } from '@backstage/core-components';
import { ScaffolderTaskOutput } from '@backstage/plugin-scaffolder-react';
import { Box, Paper } from '@material-ui/core';
import React, { useMemo, useState } from 'react';
import { LinkOutputs } from './LinkOutputs';
import { TextOutputs } from './TextOutputs';

/**
 * The DefaultOutputs renderer for the scaffolder task output
 *
 * @alpha
 */
export const DefaultTemplateOutputs = (props: {
  output?: ScaffolderTaskOutput;
}) => {
  const [textOutputIndex, setTextOutputIndex] = useState<number | undefined>();

  const textOutput = useMemo(
    () =>
      textOutputIndex !== undefined
        ? props.output?.text?.[textOutputIndex]
        : null,
    [props.output, textOutputIndex],
  );

  if (!props.output) {
    return null;
  }

  return (
    <>
      <Box paddingBottom={2}>
        <Paper>
          <Box padding={2} justifyContent="center" display="flex" gridGap={16}>
            <TextOutputs
              output={props.output}
              index={textOutputIndex}
              setIndex={setTextOutputIndex}
            />
            <LinkOutputs output={props.output} />
          </Box>
        </Paper>
      </Box>
      {textOutput ? (
        <Box paddingBottom={2}>
          <InfoCard
            title={textOutput.title ?? 'Text Output'}
            noPadding
            titleTypographyProps={{ component: 'h2' }}
          >
            <Box padding={2} height="100%">
              <MarkdownContent content={textOutput.content ?? ''} />
            </Box>
          </InfoCard>
        </Box>
      ) : null}
    </>
  );
};

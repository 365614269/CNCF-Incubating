/*
 * Copyright 2020 The Backstage Authors
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

import { ComponentEntity, RELATION_HAS_PART } from '@backstage/catalog-model';
import {
  InfoCardVariants,
  TableColumn,
  TableOptions,
} from '@backstage/core-components';
import {
  asComponentEntities,
  componentEntityColumns,
  componentEntityHelpLink,
  RelatedEntitiesCard,
} from '../RelatedEntitiesCard';
import { catalogTranslationRef } from '../../alpha/translation';
import { useTranslationRef } from '@backstage/core-plugin-api/alpha';

/** @public */
export interface HasComponentsCardProps {
  variant?: InfoCardVariants;
  title?: string;
  columns?: TableColumn<ComponentEntity>[];
  tableOptions?: TableOptions;
}

export function HasComponentsCard(props: HasComponentsCardProps) {
  const { t } = useTranslationRef(catalogTranslationRef);
  const {
    variant = 'gridItem',
    title = t('hasComponentsCard.title'),
    columns = componentEntityColumns,
    tableOptions = {},
  } = props;
  return (
    <RelatedEntitiesCard
      variant={variant}
      title={title}
      entityKind="Component"
      relationType={RELATION_HAS_PART}
      columns={columns}
      emptyMessage={t('hasComponentsCard.emptyMessage')}
      emptyHelpLink={componentEntityHelpLink}
      asRenderableEntities={asComponentEntities}
      tableOptions={tableOptions}
    />
  );
}

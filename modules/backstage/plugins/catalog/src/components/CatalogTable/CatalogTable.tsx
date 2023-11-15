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
import {
  ANNOTATION_EDIT_URL,
  ANNOTATION_VIEW_URL,
  Entity,
  RELATION_OWNED_BY,
  RELATION_PART_OF,
  stringifyEntityRef,
} from '@backstage/catalog-model';
import {
  CodeSnippet,
  Table,
  TableColumn,
  TableProps,
  WarningPanel,
} from '@backstage/core-components';
import {
  getEntityRelations,
  humanizeEntityRef,
  useEntityList,
  useStarredEntities,
} from '@backstage/plugin-catalog-react';
import Typography from '@material-ui/core/Typography';
import { withStyles } from '@material-ui/core/styles';
import { visuallyHidden } from '@mui/utils';
import Edit from '@material-ui/icons/Edit';
import OpenInNew from '@material-ui/icons/OpenInNew';
import Star from '@material-ui/icons/Star';
import StarBorder from '@material-ui/icons/StarBorder';
import { capitalize } from 'lodash';
import pluralize from 'pluralize';
import React, { ReactNode, useMemo } from 'react';
import { columnFactories } from './columns';
import { CatalogTableRow } from './types';

/**
 * Props for {@link CatalogTable}.
 *
 * @public
 */
export interface CatalogTableProps {
  columns?: TableColumn<CatalogTableRow>[];
  actions?: TableProps<CatalogTableRow>['actions'];
  tableOptions?: TableProps<CatalogTableRow>['options'];
  emptyContent?: ReactNode;
  subtitle?: string;
}

const YellowStar = withStyles({
  root: {
    color: '#f3ba37',
  },
})(Star);

const refCompare = (a: Entity, b: Entity) => {
  const toRef = (entity: Entity) =>
    entity.metadata.title ||
    humanizeEntityRef(entity, {
      defaultKind: 'Component',
    });

  return toRef(a).localeCompare(toRef(b));
};

/** @public */
export const CatalogTable = (props: CatalogTableProps) => {
  const { columns, actions, tableOptions, subtitle, emptyContent } = props;
  const { isStarredEntity, toggleStarredEntity } = useStarredEntities();
  const { loading, error, entities, filters } = useEntityList();

  const defaultColumns: TableColumn<CatalogTableRow>[] = useMemo(() => {
    return [
      columnFactories.createTitleColumn({ hidden: true }),
      columnFactories.createNameColumn({ defaultKind: filters.kind?.value }),
      ...createEntitySpecificColumns(),
      columnFactories.createMetadataDescriptionColumn(),
      columnFactories.createTagsColumn(),
    ];

    function createEntitySpecificColumns(): TableColumn<CatalogTableRow>[] {
      const baseColumns = [
        columnFactories.createSystemColumn(),
        columnFactories.createOwnerColumn(),
        columnFactories.createSpecTypeColumn(),
        columnFactories.createSpecLifecycleColumn(),
      ];
      switch (filters.kind?.value) {
        case 'user':
          return [];
        case 'domain':
        case 'system':
          return [columnFactories.createOwnerColumn()];
        case 'group':
        case 'template':
          return [columnFactories.createSpecTypeColumn()];
        case 'location':
          return [
            columnFactories.createSpecTypeColumn(),
            columnFactories.createSpecTargetsColumn(),
          ];
        default:
          return entities.every(
            entity => entity.metadata.namespace === 'default',
          )
            ? baseColumns
            : [...baseColumns, columnFactories.createNamespaceColumn()];
      }
    }
  }, [filters.kind?.value, entities]);

  const showTypeColumn = filters.type === undefined;
  // TODO(timbonicus): remove the title from the CatalogTable once using EntitySearchBar
  const titlePreamble = capitalize(filters.user?.value ?? 'all');

  if (error) {
    return (
      <div>
        <WarningPanel
          severity="error"
          title="Could not fetch catalog entities."
        >
          <CodeSnippet language="text" text={error.toString()} />
        </WarningPanel>
      </div>
    );
  }

  const defaultActions: TableProps<CatalogTableRow>['actions'] = [
    ({ entity }) => {
      const url = entity.metadata.annotations?.[ANNOTATION_VIEW_URL];
      const title = 'View';

      return {
        icon: () => (
          <>
            <Typography style={visuallyHidden}>{title}</Typography>
            <OpenInNew fontSize="small" />
          </>
        ),
        tooltip: title,
        disabled: !url,
        onClick: () => {
          if (!url) return;
          window.open(url, '_blank');
        },
      };
    },
    ({ entity }) => {
      const url = entity.metadata.annotations?.[ANNOTATION_EDIT_URL];
      const title = 'Edit';

      return {
        icon: () => (
          <>
            <Typography style={visuallyHidden}>{title}</Typography>
            <Edit fontSize="small" />
          </>
        ),
        tooltip: title,
        disabled: !url,
        onClick: () => {
          if (!url) return;
          window.open(url, '_blank');
        },
      };
    },
    ({ entity }) => {
      const isStarred = isStarredEntity(entity);
      const title = isStarred ? 'Remove from favorites' : 'Add to favorites';

      return {
        cellStyle: { paddingLeft: '1em' },
        icon: () => (
          <>
            <Typography style={visuallyHidden}>{title}</Typography>
            {isStarred ? <YellowStar /> : <StarBorder />}
          </>
        ),
        tooltip: title,
        onClick: () => toggleStarredEntity(entity),
      };
    },
  ];

  const rows = entities.sort(refCompare).map(entity => {
    const partOfSystemRelations = getEntityRelations(entity, RELATION_PART_OF, {
      kind: 'system',
    });
    const ownedByRelations = getEntityRelations(entity, RELATION_OWNED_BY);

    return {
      entity,
      resolved: {
        // This name is here for backwards compatibility mostly; the
        // presentation of refs in the table should in general be handled with
        // EntityRefLink / EntityName components
        name: humanizeEntityRef(entity, {
          defaultKind: 'Component',
        }),
        entityRef: stringifyEntityRef(entity),
        ownedByRelationsTitle: ownedByRelations
          .map(r => humanizeEntityRef(r, { defaultKind: 'group' }))
          .join(', '),
        ownedByRelations,
        partOfSystemRelationTitle: partOfSystemRelations
          .map(r =>
            humanizeEntityRef(r, {
              defaultKind: 'system',
            }),
          )
          .join(', '),
        partOfSystemRelations,
      },
    };
  });

  const typeColumn = (columns || defaultColumns).find(c => c.title === 'Type');
  if (typeColumn) {
    typeColumn.hidden = !showTypeColumn;
  }
  const showPagination = rows.length > 20;
  const currentKind = filters.kind?.value || '';
  const currentType = filters.type?.value || '';
  const titleDisplay = [titlePreamble, currentType, pluralize(currentKind)]
    .filter(s => s)
    .join(' ');

  return (
    <Table<CatalogTableRow>
      isLoading={loading}
      columns={columns || defaultColumns}
      options={{
        paging: showPagination,
        pageSize: 20,
        actionsColumnIndex: -1,
        loadingType: 'linear',
        showEmptyDataSourceMessage: !loading,
        padding: 'dense',
        pageSizeOptions: [20, 50, 100],
        ...tableOptions,
      }}
      title={`${titleDisplay} (${entities.length})`}
      data={rows}
      actions={actions || defaultActions}
      subtitle={subtitle}
      emptyContent={emptyContent}
    />
  );
};

CatalogTable.columns = columnFactories;

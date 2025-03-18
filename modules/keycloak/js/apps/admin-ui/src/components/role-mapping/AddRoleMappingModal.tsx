import RoleRepresentation from "@keycloak/keycloak-admin-client/lib/defs/roleRepresentation";
import {
  KeycloakDataTable,
  ListEmptyState,
} from "@keycloak/keycloak-ui-shared";
import {
  Button,
  Dropdown,
  DropdownItem,
  DropdownList,
  MenuToggle,
  Modal,
  ModalVariant,
  ToolbarItem,
} from "@patternfly/react-core";
import { FilterIcon } from "@patternfly/react-icons";
import { cellWidth, TableText } from "@patternfly/react-table";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useAdminClient } from "../../admin-client";
import { useAccess } from "../../context/access/Access";
import { translationFormatter } from "../../utils/translationFormatter";
import useLocaleSort from "../../utils/useLocaleSort";
import { ResourcesKey, Row, ServiceRole } from "./RoleMapping";
import { getAvailableRoles } from "./queries";
import { getAvailableClientRoles } from "./resource";
import { PermissionsConfigurationTabsParams } from "../../permissions-configuration/routes/PermissionsConfigurationTabs";
import { useParams } from "react-router-dom";

type AddRoleMappingModalProps = {
  id: string;
  type: ResourcesKey;
  name?: string;
  isRadio?: boolean;
  onAssign: (rows: Row[]) => void;
  onClose: () => void;
  isLDAPmapper?: boolean;
};

type FilterType = "roles" | "clients";

const RoleDescription = ({ role }: { role: RoleRepresentation }) => {
  const { t } = useTranslation();
  return (
    <TableText wrapModifier="truncate">
      {translationFormatter(t)(role.description) as string}
    </TableText>
  );
};

export const AddRoleMappingModal = ({
  id,
  name,
  type,
  isLDAPmapper,
  onAssign,
  onClose,
}: AddRoleMappingModalProps) => {
  const { adminClient } = useAdminClient();

  const { t } = useTranslation();
  const { hasAccess } = useAccess();
  const canViewRealmRoles = hasAccess("view-realm") || hasAccess("query-users");

  const [searchToggle, setSearchToggle] = useState(false);

  const [filterType, setFilterType] = useState<FilterType>("clients");
  const [selectedRows, setSelectedRows] = useState<Row[]>([]);
  const [key, setKey] = useState(0);
  const refresh = () => setKey(key + 1);

  const localeSort = useLocaleSort();
  const compareRow = ({ role: { name } }: Row) => name?.toUpperCase();
  const { tab } = useParams<PermissionsConfigurationTabsParams>();

  const loader = async (
    first?: number,
    max?: number,
    search?: string,
  ): Promise<Row[]> => {
    const params: Record<string, string | number> = {
      first: first!,
      max: max!,
    };

    if (search) {
      params.search = search;
    }

    const roles = await getAvailableRoles(adminClient, type, { ...params, id });
    const sorted = localeSort(roles, compareRow);
    return sorted.map((row) => {
      return {
        role: row.role,
        id: row.role.id,
      };
    });
  };

  const clientRolesLoader = async (
    first?: number,
    max?: number,
    search?: string,
  ): Promise<Row[]> => {
    const roles = await getAvailableClientRoles(adminClient, {
      id,
      type,
      first: first || 0,
      max: max || 10,
      search,
    });

    return localeSort(
      roles.map((e) => ({
        client: { clientId: e.client, id: e.clientId },
        role: { id: e.id, name: e.role, description: e.description },
        id: e.id,
      })),
      ({ client: { clientId }, role: { name } }) => `${clientId}${name}`,
    );
  };

  return (
    <Modal
      variant={ModalVariant.large}
      title={
        tab !== "evaluation"
          ? isLDAPmapper
            ? t("assignRole")
            : t("assignRolesTo", { client: name })
          : t("selectRole")
      }
      isOpen
      onClose={onClose}
      actions={[
        <Button
          data-testid="assign"
          key="confirm"
          isDisabled={selectedRows.length === 0}
          variant="primary"
          onClick={() => {
            onAssign(selectedRows);
            onClose();
          }}
        >
          {tab !== "evaluation" ? t("assign") : t("select")}
        </Button>,
        <Button
          data-testid="cancel"
          key="cancel"
          variant="link"
          onClick={onClose}
        >
          {t("cancel")}
        </Button>,
      ]}
    >
      <KeycloakDataTable
        key={key}
        onSelect={(rows) => {
          if (tab === "evaluation") {
            setSelectedRows(rows.length > 0 ? [rows[0]] : []);
          } else {
            setSelectedRows([...rows]);
          }
        }}
        searchPlaceholderKey="searchByRoleName"
        isPaginated={!(filterType === "roles" && type !== "roles")}
        searchTypeComponent={
          canViewRealmRoles && (
            <ToolbarItem>
              <Dropdown
                onOpenChange={(isOpen) => setSearchToggle(isOpen)}
                onSelect={() => {
                  setFilterType(filterType === "roles" ? "clients" : "roles");
                  setSearchToggle(false);
                  refresh();
                }}
                toggle={(ref) => (
                  <MenuToggle
                    data-testid="filter-type-dropdown"
                    ref={ref}
                    onClick={() => setSearchToggle(!searchToggle)}
                    icon={<FilterIcon />}
                  >
                    {filterType === "roles"
                      ? t("filterByRoles")
                      : t("filterByClients")}
                  </MenuToggle>
                )}
                isOpen={searchToggle}
              >
                <DropdownList>
                  <DropdownItem key="filter-type" data-testid={filterType}>
                    {filterType === "roles"
                      ? t("filterByClients")
                      : t("filterByRoles")}
                  </DropdownItem>
                </DropdownList>
              </Dropdown>
            </ToolbarItem>
          )
        }
        canSelectAll
        isRadio={tab === "evaluation"}
        loader={filterType === "roles" ? loader : clientRolesLoader}
        ariaLabelKey="associatedRolesText"
        columns={[
          {
            name: "name",
            cellRenderer: ServiceRole,
            transforms: [cellWidth(30)],
          },
          {
            name: "role.description",
            displayKey: "description",
            cellRenderer: RoleDescription,
          },
        ]}
        emptyState={
          <ListEmptyState
            message={t("noRoles")}
            instructions={t("noRealmRolesToAssign")}
            secondaryActions={[
              {
                text: t("filterByRoles"),
                onClick: () => {
                  setFilterType("roles");
                  refresh();
                },
              },
            ]}
          />
        }
      />
    </Modal>
  );
};

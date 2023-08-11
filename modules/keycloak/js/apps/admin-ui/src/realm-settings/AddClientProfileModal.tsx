import type ClientProfileRepresentation from "@keycloak/keycloak-admin-client/lib/defs/clientProfileRepresentation";
import type RoleRepresentation from "@keycloak/keycloak-admin-client/lib/defs/roleRepresentation";
import { Button, Label, Modal, ModalVariant } from "@patternfly/react-core";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { adminClient } from "../admin-client";
import { KeycloakSpinner } from "../components/keycloak-spinner/KeycloakSpinner";
import { ListEmptyState } from "../components/list-empty-state/ListEmptyState";
import { KeycloakDataTable } from "../components/table-toolbar/KeycloakDataTable";
import { useFetch } from "../utils/useFetch";

type ClientProfile = ClientProfileRepresentation & {
  global: boolean;
};

const AliasRenderer = ({ name, global }: ClientProfile) => {
  const { t } = useTranslation("roles");

  return (
    <>
      {name}{" "}
      {global && <Label color="blue">{t("realm-settings:global")}</Label>}
    </>
  );
};

export type AddClientProfileModalProps = {
  open: boolean;
  toggleDialog: () => void;
  onConfirm: (newReps: RoleRepresentation[]) => void;
  allProfiles: string[];
};

export const AddClientProfileModal = (props: AddClientProfileModalProps) => {
  const { t } = useTranslation("roles");
  const [selectedRows, setSelectedRows] = useState<RoleRepresentation[]>([]);

  const [tableProfiles, setTableProfiles] = useState<ClientProfile[]>();

  useFetch(
    () =>
      adminClient.clientPolicies.listProfiles({
        includeGlobalProfiles: true,
      }),
    (allProfiles) => {
      const globalProfiles = allProfiles.globalProfiles?.map(
        (globalProfiles) => ({
          ...globalProfiles,
          global: true,
        }),
      );

      const profiles = allProfiles.profiles?.map((profiles) => ({
        ...profiles,
        global: false,
      }));

      setTableProfiles([...(globalProfiles ?? []), ...(profiles ?? [])]);
    },
    [],
  );

  const loader = async () =>
    tableProfiles?.filter((item) => !props.allProfiles.includes(item.name!)) ??
    [];

  if (!tableProfiles) {
    return <KeycloakSpinner />;
  }

  return (
    <Modal
      data-testid="addClientProfile"
      title={t("realm-settings:addClientProfile")}
      isOpen={props.open}
      onClose={props.toggleDialog}
      variant={ModalVariant.large}
      actions={[
        <Button
          key="add"
          data-testid="add-client-profile-button"
          variant="primary"
          isDisabled={!selectedRows.length}
          onClick={() => {
            props.toggleDialog();
            props.onConfirm(selectedRows);
          }}
        >
          {t("common:add")}
        </Button>,
        <Button
          key="cancel"
          variant="link"
          onClick={() => {
            props.toggleDialog();
          }}
        >
          {t("common:cancel")}
        </Button>,
      ]}
    >
      <KeycloakDataTable
        loader={loader}
        ariaLabelKey="realm-settings:profilesList"
        searchPlaceholderKey="realm-settings:searchProfile"
        canSelectAll
        onSelect={(rows) => {
          setSelectedRows([...rows]);
        }}
        columns={[
          {
            name: "name",
            displayKey: "realm-settings:clientProfileName",
            cellRenderer: AliasRenderer,
          },
          {
            name: "description",
            displayKey: "common:description",
          },
        ]}
        emptyState={
          <ListEmptyState
            hasIcon
            message={t("noRoles")}
            instructions={t("noRolesInstructions")}
            primaryActionText={t("createRole")}
          />
        }
      />
    </Modal>
  );
};

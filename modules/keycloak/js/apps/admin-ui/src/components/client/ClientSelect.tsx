import type ClientRepresentation from "@keycloak/keycloak-admin-client/lib/defs/clientRepresentation";
import type { ClientQuery } from "@keycloak/keycloak-admin-client/lib/resources/clients";
import {
  SelectControl,
  SelectVariant,
  useFetch,
} from "@keycloak/keycloak-ui-shared";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useAdminClient } from "../../admin-client";
import type { ComponentProps } from "../dynamic/components";
import { PermissionsConfigurationTabsParams } from "../../permissions-configuration/routes/PermissionsConfigurationTabs";
import { useParams } from "react-router-dom";

type ClientSelectProps = Omit<ComponentProps, "convertToName"> & {
  variant?: `${SelectVariant}`;
  isRequired?: boolean;
  clientKey?: keyof ClientRepresentation;
  placeholderText?: string;
};

export const ClientSelect = ({
  name,
  label,
  helpText,
  defaultValue,
  isDisabled = false,
  isRequired,
  variant = "typeahead",
  clientKey = "clientId",
  placeholderText,
}: ClientSelectProps) => {
  const { adminClient } = useAdminClient();

  const { t } = useTranslation();

  const [clients, setClients] = useState<ClientRepresentation[]>([]);
  const [search, setSearch] = useState("");
  const { tab } = useParams<PermissionsConfigurationTabsParams>();

  useFetch(
    () => {
      const params: ClientQuery = {
        max: 20,
      };
      if (search) {
        params.clientId = search;
        params.search = true;
      }
      return adminClient.clients.find(params);
    },
    (clients) => setClients(clients),
    [search],
  );

  return (
    <SelectControl
      name={name!}
      label={tab !== "evaluation" ? t(label!) : t("client")}
      labelIcon={tab !== "evaluation" ? t(helpText!) : t("selectClient")}
      controller={{
        defaultValue: defaultValue || "",
        rules: {
          required: {
            value: isRequired || false,
            message: t("required"),
          },
        },
      }}
      onFilter={(value) => setSearch(value)}
      variant={variant}
      isDisabled={isDisabled}
      options={clients.map((client) => ({
        key: client[clientKey] as string,
        value: client.clientId!,
      }))}
      placeholderText={placeholderText}
    />
  );
};

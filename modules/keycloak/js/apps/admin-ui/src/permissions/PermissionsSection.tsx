import type ClientRepresentation from "@keycloak/keycloak-admin-client/lib/defs/clientRepresentation";
import { useAlerts, useFetch } from "@keycloak/keycloak-ui-shared";
import { useState } from "react";
import { useAdminClient } from "../admin-client";
import { ViewHeader } from "../components/view-header/ViewHeader";
import {
  RoutableTabs,
  useRoutableTab,
} from "../components/routable-tabs/RoutableTabs";
import {
  PermissionsTabs,
  toPermissionsTabs,
} from "../permissions/routes/PermissionsTabs";
import {
  AlertVariant,
  PageSection,
  Tab,
  TabTitleText,
} from "@patternfly/react-core";
import { AuthorizationResources } from "../clients/authorization/Resources";
import { AuthorizationPolicies } from "../clients/authorization/Policies";
import { AuthorizationEvaluate } from "../clients/authorization/AuthorizationEvaluate";
import { useRealm } from "../context/realm-context/RealmContext";
import { useAccess } from "../context/access/Access";
import { useTranslation } from "react-i18next";
import { FormProvider, useForm, useWatch } from "react-hook-form";
import { FormFields, SaveOptions } from "../clients/ClientDetails";
import {
  convertAttributeNameToForm,
  convertFormValuesToObject,
  convertToFormValues,
} from "../util";
import { ConfirmDialogModal } from "../components/confirm-dialog/ConfirmDialog";
import { KeyValueType } from "../components/key-value-form/key-value-convert";
import useToggle from "../utils/useToggle";

export default function PermissionsSection() {
  const { adminClient } = useAdminClient();
  const { t } = useTranslation();
  const { realm } = useRealm();
  const { hasAccess } = useAccess();
  const { addAlert, addError } = useAlerts();
  const [adminPermissionsClient, setAdminPermissionsClient] = useState<
    ClientRepresentation | undefined
  >();
  const [changeAuthenticatorOpen, toggleChangeAuthenticatorOpen] = useToggle();
  const form = useForm<FormFields>();

  const usePermissionsTabs = (tab: PermissionsTabs) =>
    useRoutableTab(
      toPermissionsTabs({
        realm,
        tab,
      }),
    );

  const clientAuthenticatorType = useWatch({
    control: form.control,
    name: "clientAuthenticatorType",
    defaultValue: "client-secret",
  });

  const hasManageAuthorization = hasAccess("manage-authorization");
  const hasViewUsers = hasAccess("view-users");
  const permissionsResourcesTab = usePermissionsTabs("resources");
  const permissionsPoliciesTab = usePermissionsTabs("policies");
  const permissionsEvaluateTab = usePermissionsTabs("evaluate");

  useFetch(
    async () => {
      const clients = await adminClient.clients.find();
      return clients;
    },
    (clients) => {
      const adminPermissionsClient = clients.find(
        (client) => client.clientId === "admin-permissions",
      );
      setAdminPermissionsClient(adminPermissionsClient!);
    },
    [],
  );

  const setupForm = (client: ClientRepresentation) => {
    form.reset({ ...client });
    convertToFormValues(client, form.setValue);
    if (client.attributes?.["acr.loa.map"]) {
      form.setValue(
        convertAttributeNameToForm("attributes.acr.loa.map"),
        // @ts-ignore
        Object.entries(JSON.parse(client.attributes["acr.loa.map"])).flatMap(
          ([key, value]) => ({ key, value }),
        ),
      );
    }
  };

  const save = async (
    { confirmed = false, messageKey = "clientSaveSuccess" }: SaveOptions = {
      confirmed: false,
      messageKey: "clientSaveSuccess",
    },
  ) => {
    if (!(await form.trigger())) {
      return;
    }

    if (
      !adminPermissionsClient?.publicClient &&
      adminPermissionsClient?.clientAuthenticatorType !==
        clientAuthenticatorType &&
      !confirmed
    ) {
      toggleChangeAuthenticatorOpen();
      return;
    }

    const values = convertFormValuesToObject(form.getValues());

    const submittedClient =
      convertFormValuesToObject<ClientRepresentation>(values);

    if (submittedClient.attributes?.["acr.loa.map"]) {
      submittedClient.attributes["acr.loa.map"] = JSON.stringify(
        Object.fromEntries(
          (submittedClient.attributes["acr.loa.map"] as KeyValueType[])
            .filter(({ key }) => key !== "")
            .map(({ key, value }) => [key, value]),
        ),
      );
    }

    try {
      const newClient: ClientRepresentation = {
        ...adminPermissionsClient,
        ...submittedClient,
      };

      newClient.clientId = newClient.clientId?.trim();

      await adminClient.clients.update(
        { id: adminPermissionsClient!.clientId! },
        newClient,
      );
      setupForm(newClient);
      setAdminPermissionsClient(newClient);
      addAlert(t(messageKey), AlertVariant.success);
    } catch (error) {
      addError("clientSaveError", error);
    }
  };

  return (
    adminPermissionsClient && (
      <>
        <ConfirmDialogModal
          continueButtonLabel="yes"
          cancelButtonLabel="no"
          titleKey={t("changeAuthenticatorConfirmTitle", {
            clientAuthenticatorType: clientAuthenticatorType,
          })}
          open={changeAuthenticatorOpen}
          toggleDialog={toggleChangeAuthenticatorOpen}
          onConfirm={() => save({ confirmed: true })}
        >
          <>
            {t("changeAuthenticatorConfirm", {
              clientAuthenticatorType: clientAuthenticatorType,
            })}
          </>
        </ConfirmDialogModal>
        <PageSection variant="light" className="pf-v5-u-p-0">
          <FormProvider {...form}>
            <ViewHeader
              titleKey={t("permissions")}
              subKey={t("permissionsSubTitle")}
            />
            <RoutableTabs
              mountOnEnter
              unmountOnExit
              defaultLocation={toPermissionsTabs({
                realm,
                tab: "resources",
              })}
            >
              <Tab
                id="resources"
                data-testid="permissionsResources"
                title={<TabTitleText>{t("resources")}</TabTitleText>}
                {...permissionsResourcesTab}
              >
                <AuthorizationResources clientId={adminPermissionsClient.id!} />
              </Tab>
              <Tab
                id="policies"
                data-testid="permissionsPolicies"
                title={<TabTitleText>{t("policies")}</TabTitleText>}
                {...permissionsPoliciesTab}
              >
                <AuthorizationPolicies
                  clientId={adminPermissionsClient.id!}
                  isDisabled={!hasManageAuthorization}
                />
              </Tab>
              {hasViewUsers && (
                <Tab
                  id="evaluate"
                  data-testid="permissionsEvaluate"
                  title={<TabTitleText>{t("evaluate")}</TabTitleText>}
                  {...permissionsEvaluateTab}
                >
                  <AuthorizationEvaluate
                    client={adminPermissionsClient}
                    save={save}
                  />
                </Tab>
              )}
            </RoutableTabs>
          </FormProvider>
        </PageSection>
      </>
    )
  );
}

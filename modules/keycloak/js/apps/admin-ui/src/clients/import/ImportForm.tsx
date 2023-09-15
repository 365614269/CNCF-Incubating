import type ClientRepresentation from "@keycloak/keycloak-admin-client/lib/defs/clientRepresentation";
import { Language } from "@patternfly/react-code-editor";
import {
  ActionGroup,
  AlertVariant,
  Button,
  FormGroup,
  PageSection,
} from "@patternfly/react-core";
import { useState } from "react";
import { FormProvider, useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router-dom";

import { adminClient } from "../../admin-client";
import { useAlerts } from "../../components/alert/Alerts";
import { FormAccess } from "../../components/form/FormAccess";
import { FileUploadForm } from "../../components/json-file-upload/FileUploadForm";
import { KeycloakTextInput } from "../../components/keycloak-text-input/KeycloakTextInput";
import { ViewHeader } from "../../components/view-header/ViewHeader";
import { useRealm } from "../../context/realm-context/RealmContext";
import {
  addTrailingSlash,
  convertFormValuesToObject,
  convertToFormValues,
} from "../../util";
import { getAuthorizationHeaders } from "../../utils/getAuthorizationHeaders";
import { ClientDescription } from "../ClientDescription";
import { FormFields } from "../ClientDetails";
import { CapabilityConfig } from "../add/CapabilityConfig";
import { toClient } from "../routes/Client";
import { toClients } from "../routes/Clients";

const isXml = (text: string) => text.match(/(<.[^(><.)]+>)/g);

export default function ImportForm() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { realm } = useRealm();
  const form = useForm<FormFields>();
  const { register, handleSubmit, setValue } = form;
  const [imported, setImported] = useState<ClientRepresentation>({});

  const { addAlert, addError } = useAlerts();

  const handleFileChange = async (contents: string) => {
    try {
      const parsed = await parseFileContents(contents);

      convertToFormValues(parsed, setValue);
      setImported(parsed);
    } catch (error) {
      addError("importParseError", error);
    }
  };

  async function parseFileContents(
    contents: string,
  ): Promise<ClientRepresentation> {
    if (!isXml(contents)) {
      return JSON.parse(contents);
    }

    const response = await fetch(
      `${addTrailingSlash(
        adminClient.baseUrl,
      )}admin/realms/${realm}/client-description-converter`,
      {
        method: "POST",
        body: contents,
        headers: getAuthorizationHeaders(await adminClient.getAccessToken()),
      },
    );

    if (!response.ok) {
      throw new Error(
        `Server responded with invalid status: ${response.statusText}`,
      );
    }

    return response.json();
  }

  const save = async (client: ClientRepresentation) => {
    try {
      const newClient = await adminClient.clients.create({
        ...imported,
        ...convertFormValuesToObject({
          ...client,
          attributes: client.attributes || {},
        }),
      });
      addAlert(t("clientImportSuccess"), AlertVariant.success);
      navigate(toClient({ realm, clientId: newClient.id, tab: "settings" }));
    } catch (error) {
      addError("clientImportError", error);
    }
  };

  return (
    <>
      <ViewHeader titleKey="importClient" subKey="clientsExplain" />
      <PageSection variant="light">
        <FormAccess
          isHorizontal
          onSubmit={handleSubmit(save)}
          role="manage-clients"
        >
          <FormProvider {...form}>
            <FileUploadForm
              id="realm-file"
              language={Language.json}
              extension=".json,.xml"
              helpText={t("helpFileUploadClient")}
              onChange={handleFileChange}
            />
            <ClientDescription hasConfigureAccess />
            <FormGroup label={t("type")} fieldId="kc-type">
              <KeycloakTextInput
                id="kc-type"
                isReadOnly
                {...register("protocol")}
              />
            </FormGroup>
            <CapabilityConfig unWrap={true} />
            <ActionGroup>
              <Button variant="primary" type="submit">
                {t("save")}
              </Button>
              <Button
                variant="link"
                component={(props) => (
                  <Link {...props} to={toClients({ realm })} />
                )}
              >
                {t("cancel")}
              </Button>
            </ActionGroup>
          </FormProvider>
        </FormAccess>
      </PageSection>
    </>
  );
}

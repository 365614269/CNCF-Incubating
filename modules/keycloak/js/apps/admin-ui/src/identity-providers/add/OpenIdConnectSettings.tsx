import { FormGroup, Title } from "@patternfly/react-core";
import { useFormContext } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { HelpItem } from "ui-shared";

import { adminClient } from "../../admin-client";
import { JsonFileUpload } from "../../components/json-file-upload/JsonFileUpload";
import { DiscoveryEndpointField } from "../component/DiscoveryEndpointField";
import { DiscoverySettings } from "./DiscoverySettings";

export const OpenIdConnectSettings = () => {
  const { t } = useTranslation();
  const id = "oidc";

  const {
    setValue,
    setError,
    clearErrors,
    formState: { errors },
  } = useFormContext();

  const setupForm = (result: any) => {
    Object.keys(result).map((k) => setValue(`config.${k}`, result[k]));
  };

  const fileUpload = async (obj?: object) => {
    clearErrors("discoveryError");
    if (!obj) {
      return;
    }

    const formData = new FormData();
    formData.append("providerId", id);
    formData.append("file", new Blob([JSON.stringify(obj)]));

    try {
      const result =
        await adminClient.identityProviders.importFromUrl(formData);
      setupForm(result);
    } catch (error) {
      setError("discoveryError", {
        type: "manual",
        message: (error as Error).message,
      });
    }
  };

  return (
    <>
      <Title headingLevel="h2" size="xl" className="kc-form-panel__title">
        {t("oidcSettings")}
      </Title>

      <DiscoveryEndpointField
        id="oidc"
        fileUpload={
          <FormGroup
            label={t("importConfig")}
            fieldId="kc-import-config"
            labelIcon={
              <HelpItem
                helpText={t("importConfigHelp")}
                fieldLabelId="importConfig"
              />
            }
            validated={errors.discoveryError ? "error" : "default"}
            helperTextInvalid={errors.discoveryError?.message as string}
          >
            <JsonFileUpload
              id="kc-import-config"
              helpText={t("identity=providers-help:jsonFileUpload")}
              hideDefaultPreview
              unWrap
              validated={errors.discoveryError ? "error" : "default"}
              onChange={(value) => fileUpload(value)}
            />
          </FormGroup>
        }
      >
        {(readonly) => <DiscoverySettings readOnly={readonly} />}
      </DiscoveryEndpointField>
    </>
  );
};

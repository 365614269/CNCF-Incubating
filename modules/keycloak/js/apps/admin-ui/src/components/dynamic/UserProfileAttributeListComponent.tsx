import type { UserProfileConfig } from "@keycloak/keycloak-admin-client/lib/defs/userProfileMetadata";
import { FormGroup } from "@patternfly/react-core";
import { useState } from "react";
import { useFormContext } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { HelpItem } from "ui-shared";

import { adminClient } from "../../admin-client";
import { useFetch } from "../../utils/useFetch";
import { KeySelect } from "../key-value-form/KeySelect";
import { convertToName } from "./DynamicComponents";
import type { ComponentProps } from "./components";

export const UserProfileAttributeListComponent = ({
  name,
  label,
  helpText,
  required = false,
}: ComponentProps) => {
  const { t } = useTranslation();
  const {
    formState: { errors },
  } = useFormContext();

  const [config, setConfig] = useState<UserProfileConfig>();
  const convertedName = convertToName(name!);

  useFetch(
    () => adminClient.users.getProfile(),
    (cfg) => setConfig(cfg),
    [],
  );

  const convert = (config?: UserProfileConfig) => {
    if (!config?.attributes) return [];

    return config.attributes.map((option) => ({
      key: option.name!,
      label: option.name!,
    }));
  };

  if (!config) return null;

  return (
    <FormGroup
      label={t(label!)}
      isRequired={required}
      labelIcon={<HelpItem helpText={t(helpText!)} fieldLabelId={label!} />}
      fieldId={convertedName!}
      validated={errors[convertedName!] ? "error" : "default"}
      helperTextInvalid={t("required")}
    >
      <KeySelect
        name={convertedName}
        rules={required ? { required: true } : {}}
        selectItems={convert(config)}
      />
    </FormGroup>
  );
};

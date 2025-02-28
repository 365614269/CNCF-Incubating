import { useTranslation } from "react-i18next";
import { FormGroup, Radio } from "@patternfly/react-core";
import { HelpItem } from "@keycloak/keycloak-ui-shared";
import { useFormContext } from "react-hook-form";
import { useState, type JSX } from "react";
import { UserSelect } from "../../components/users/UserSelect";
import { ClientSelect } from "../../components/client/ClientSelect";
import { GroupSelect } from "./GroupSelect";

type ResourceTypeProps = {
  resourceType: string;
};

const COMPONENTS: {
  [index: string]: (props: any) => JSX.Element;
} = {
  users: UserSelect,
  clients: ClientSelect,
  groups: GroupSelect,
} as const;

export const isValidComponentType = (value: string) => value in COMPONENTS;

export const ResourceType = ({ resourceType }: ResourceTypeProps) => {
  const { t } = useTranslation();
  const form = useFormContext();
  const resourceIds: string[] = form.getValues("resources");

  const [isSpecificResources, setIsSpecificResources] = useState(
    resourceIds.some((id) => id !== resourceType),
  );

  function getComponentType() {
    const selectedResourceType = resourceType.toLowerCase();
    if (isValidComponentType(selectedResourceType)) {
      return COMPONENTS[selectedResourceType];
    }
    return null;
  }

  const ComponentType = getComponentType();

  return (
    <>
      <FormGroup
        label={t("EnforceAccessTo")}
        labelIcon={
          <HelpItem
            helpText={t("enforceAccessToHelpText")}
            fieldLabelId="enforce-access-to"
          />
        }
        fieldId="EnforceAccessTo"
        hasNoPaddingTop
        isRequired
      >
        <Radio
          id="allResources"
          data-testid="allResources"
          isChecked={!isSpecificResources}
          name="EnforceAccessTo"
          label={t(`allResourceType`, { resourceType })}
          onChange={() => {
            setIsSpecificResources(false);
            form.setValue("resources", []);
          }}
          className="pf-v5-u-mb-md"
        />
        <Radio
          id="specificResources"
          data-testid="specificResources"
          isChecked={isSpecificResources}
          name="EnforceAccessTo"
          label={t(`specificResourceType`, { resourceType })}
          onChange={() => {
            setIsSpecificResources(true);
            form.setValue("resources", []);
          }}
          className="pf-v5-u-mb-md"
        />
      </FormGroup>
      {isSpecificResources && ComponentType && (
        <ComponentType
          name="resources"
          label={`${resourceType.toLowerCase()}Resources`}
          helpText={t("resourceTypeHelpText", { resourceType })}
          defaultValue={[]}
          variant="typeaheadMulti"
        />
      )}
    </>
  );
};

import { TextInputTypes } from "@patternfly/react-core";
import { KeycloakTextInput } from "../keycloak-text-input/KeycloakTextInput";
import { UserProfileFieldProps } from "./UserProfileFields";
import { UserProfileGroup } from "./UserProfileGroup";
import { fieldName, isRequiredAttribute } from "./utils";

export const TextComponent = (props: UserProfileFieldProps) => {
  const { form, inputType, attribute } = props;
  const isRequired = isRequiredAttribute(attribute);
  const type = inputType.startsWith("html")
    ? (inputType.substring("html".length + 2) as TextInputTypes)
    : "text";

  return (
    <UserProfileGroup {...props}>
      <KeycloakTextInput
        id={attribute.name}
        data-testid={attribute.name}
        type={type}
        placeholder={attribute.annotations?.["inputTypePlaceholder"] as string}
        readOnly={attribute.readOnly}
        isRequired={isRequired}
        {...form.register(fieldName(attribute.name))}
      />
    </UserProfileGroup>
  );
};

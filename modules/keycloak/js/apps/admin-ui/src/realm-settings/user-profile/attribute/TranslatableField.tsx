import KeycloakAdminClient from "@keycloak/keycloak-admin-client";
import { FormErrorText } from "@keycloak/keycloak-ui-shared";
import {
  Alert,
  Button,
  FormHelperText,
  InputGroup,
  InputGroupItem,
  TextInput,
} from "@patternfly/react-core";
import { GlobeRouteIcon } from "@patternfly/react-icons";
import { useEffect } from "react";
import { useFormContext, useWatch } from "react-hook-form";
import { Trans, useTranslation } from "react-i18next";
import { useRealm } from "../../../context/realm-context/RealmContext";
import { i18n } from "../../../i18n/i18n";
import { beerify, debeerify } from "../../../util";
import useToggle from "../../../utils/useToggle";
import { AddTranslationsDialog } from "./AddTranslationsDialog";

export type TranslationForm = {
  locale: string;
  value: string;
};

export type Translation = Record<string, TranslationForm[]>;

export type Translations = {
  translation: Translation;
};

type SaveTranslationsProps = {
  adminClient: KeycloakAdminClient;
  realmName: string;
  translationsData: Translations;
};

export const saveTranslations = async ({
  adminClient,
  realmName,
  translationsData,
}: SaveTranslationsProps) => {
  await Promise.all(
    Object.entries(translationsData.translation)
      .map(([key, translation]) =>
        translation
          .filter((translation) => translation.value.trim() !== "")
          .map((translation) =>
            adminClient.realms.addLocalization(
              {
                realm: realmName,
                selectedLocale: translation.locale,
                key: debeerify(key),
              },
              translation.value,
            ),
          ),
      )
      .flat(),
  );
  await i18n.reloadResources();
};

type TranslatableFieldProps = {
  attributeName: string;
  prefix: string;
  fieldName: string;
};

export const TranslatableField = ({
  attributeName,
  prefix,
  fieldName,
}: TranslatableFieldProps) => {
  const { t } = useTranslation();
  const { realmRepresentation: realm } = useRealm();
  const { register, control, getFieldState, setValue } = useFormContext();
  const [open, toggle] = useToggle();

  const value = useWatch({ control, name: attributeName });

  const key = `${prefix}.${value}`;
  const translationPrefix = `translation.${beerify(key)}`;
  const requiredTranslationName = `${translationPrefix}.0.value`;

  useEffect(() => {
    if (realm?.internationalizationEnabled) {
      if (t(value) === value && value !== "") {
        setValue(fieldName, `\${${prefix}.${value}}`);
      }
    }
  }, [value]);

  return (
    <>
      {realm?.internationalizationEnabled && (
        <input
          type="hidden"
          data-testid="requiredTranslationName"
          {...register(requiredTranslationName, { required: t("required") })}
        />
      )}
      {open && (
        <AddTranslationsDialog
          orgKey={value}
          translationKey={`${prefix}.${value}`}
          fieldName={fieldName}
          toggleDialog={toggle}
        />
      )}
      <InputGroup>
        <InputGroupItem isFill>
          <TextInput
            id={`kc-attribute-${fieldName}`}
            data-testid={`attributes-${fieldName}`}
            isDisabled={realm?.internationalizationEnabled}
            {...register(fieldName)}
          />
        </InputGroupItem>
        {realm?.internationalizationEnabled && (
          <InputGroupItem>
            <Button
              variant="link"
              className="pf-m-plain"
              data-testid={`addAttribute${fieldName}TranslationBtn`}
              aria-label={t("addAttributeTranslation", { fieldName })}
              onClick={toggle}
              icon={<GlobeRouteIcon />}
            />
          </InputGroupItem>
        )}
      </InputGroup>
      {realm?.internationalizationEnabled && (
        <FormHelperText>
          <Alert
            variant="info"
            isInline
            isPlain
            title={
              <Trans
                i18nKey="addTranslationsModalSubTitle"
                values={{ fieldName }}
              >
                You are able to translate the fieldName based on your locale or
                <strong>location</strong>
              </Trans>
            }
          />
          {getFieldState(requiredTranslationName).error && (
            <FormErrorText message={t("required")} />
          )}
        </FormHelperText>
      )}
    </>
  );
};

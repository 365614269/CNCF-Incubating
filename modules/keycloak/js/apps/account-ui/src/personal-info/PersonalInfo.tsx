import {
  ActionGroup,
  Alert,
  Button,
  ExpandableSection,
  Form,
  Spinner,
} from "@patternfly/react-core";
import { ExternalLinkSquareAltIcon } from "@patternfly/react-icons";
import { TFunction } from "i18next";
import { useState } from "react";
import { ErrorOption, useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";
import {
  UserProfileFields,
  debeerify,
  setUserProfileServerError,
  useAlerts,
} from "ui-shared";

import {
  getPersonalInfo,
  getSupportedLocales,
  savePersonalInfo,
} from "../api/methods";
import {
  UserProfileMetadata,
  UserRepresentation,
} from "../api/representations";
import { Page } from "../components/page/Page";
import { TFuncKey, i18n } from "../i18n";
import { useEnvironment } from "../root/KeycloakContext";
import { usePromise } from "../utils/usePromise";

export const PersonalInfo = () => {
  const { t } = useTranslation();
  const context = useEnvironment();
  const [userProfileMetadata, setUserProfileMetadata] =
    useState<UserProfileMetadata>();
  const [supportedLocales, setSupportedLocales] = useState<string[]>([]);
  const form = useForm<UserRepresentation>({ mode: "onChange" });
  const { handleSubmit, reset, setError } = form;
  const { addAlert, addError } = useAlerts();

  usePromise(
    (signal) =>
      Promise.all([
        getPersonalInfo({ signal, context }),
        getSupportedLocales({ signal, context }),
      ]),
    ([personalInfo, supportedLocales]) => {
      setUserProfileMetadata(personalInfo.userProfileMetadata);
      setSupportedLocales(supportedLocales);
      reset(personalInfo);
    },
  );

  const onSubmit = async (user: UserRepresentation) => {
    try {
      const attributes = Object.fromEntries(
        Object.entries(user.attributes || {}).map(([k, v]) => [
          debeerify(k),
          v,
        ]),
      );
      await savePersonalInfo(context, { ...user, attributes });
      const locale = attributes["locale"]?.toString();
      i18n.changeLanguage(locale, (error) => {
        if (error) {
          console.warn("Error(s) loading locale", locale, error);
        }
      });
      context.keycloak.updateToken();
      addAlert(t("accountUpdatedMessage"));
    } catch (error) {
      addError(t("accountUpdatedError").toString());

      setUserProfileServerError(
        { responseData: { errors: error as any } },
        (name: string | number, error: unknown) =>
          setError(name as string, error as ErrorOption),
        ((key: TFuncKey, param?: object) => t(key, param as any)) as TFunction,
      );
    }
  };

  if (!userProfileMetadata) {
    return <Spinner />;
  }

  const {
    updateEmailFeatureEnabled,
    updateEmailActionEnabled,
    isRegistrationEmailAsUsername,
    isEditUserNameAllowed,
  } = context.environment.features;
  return (
    <Page title={t("personalInfo")} description={t("personalInfoDescription")}>
      <Form isHorizontal onSubmit={handleSubmit(onSubmit)}>
        <UserProfileFields
          form={form}
          userProfileMetadata={userProfileMetadata}
          supportedLocales={supportedLocales}
          t={
            ((key: unknown, params) =>
              t(key as TFuncKey, params as any)) as TFunction
          }
          renderer={(attribute) =>
            attribute.name === "email" &&
            updateEmailFeatureEnabled &&
            updateEmailActionEnabled &&
            (!isRegistrationEmailAsUsername || isEditUserNameAllowed) ? (
              <Button
                id="update-email-btn"
                variant="link"
                onClick={() =>
                  context.keycloak.login({ action: "UPDATE_EMAIL" })
                }
                icon={<ExternalLinkSquareAltIcon />}
                iconPosition="right"
              >
                {t("updateEmail")}
              </Button>
            ) : undefined
          }
        />
        <ActionGroup>
          <Button
            data-testid="save"
            type="submit"
            id="save-btn"
            variant="primary"
          >
            {t("save")}
          </Button>
          <Button
            data-testid="cancel"
            id="cancel-btn"
            variant="link"
            onClick={() => reset()}
          >
            {t("cancel")}
          </Button>
        </ActionGroup>
        {context.environment.features.deleteAccountAllowed && (
          <ExpandableSection
            data-testid="delete-account"
            toggleText={t("deleteAccount")}
          >
            <Alert
              isInline
              title={t("deleteAccount")}
              variant="danger"
              actionLinks={
                <Button
                  id="delete-account-btn"
                  variant="danger"
                  onClick={() =>
                    context.keycloak.login({
                      action: "delete_account",
                    })
                  }
                  className="delete-button"
                >
                  {t("delete")}
                </Button>
              }
            >
              {t("deleteAccountWarning")}
            </Alert>
          </ExpandableSection>
        )}
      </Form>
    </Page>
  );
};

export default PersonalInfo;

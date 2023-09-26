import type ClientProfileRepresentation from "@keycloak/keycloak-admin-client/lib/defs/clientProfileRepresentation";
import type ClientProfilesRepresentation from "@keycloak/keycloak-admin-client/lib/defs/clientProfilesRepresentation";
import {
  ActionGroup,
  AlertVariant,
  Button,
  ButtonVariant,
  DataList,
  DataListCell,
  DataListItem,
  DataListItemCells,
  DataListItemRow,
  Divider,
  DropdownItem,
  Flex,
  FlexItem,
  FormGroup,
  Label,
  PageSection,
  Text,
  TextVariants,
  ValidatedOptions,
} from "@patternfly/react-core";
import { PlusCircleIcon, TrashIcon } from "@patternfly/react-icons";
import { Fragment, useMemo, useState } from "react";
import { useFieldArray, useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router-dom";
import { HelpItem } from "ui-shared";

import { adminClient } from "../admin-client";
import { useAlerts } from "../components/alert/Alerts";
import { useConfirmDialog } from "../components/confirm-dialog/ConfirmDialog";
import { FormAccess } from "../components/form/FormAccess";
import { KeycloakSpinner } from "../components/keycloak-spinner/KeycloakSpinner";
import { KeycloakTextArea } from "../components/keycloak-text-area/KeycloakTextArea";
import { KeycloakTextInput } from "../components/keycloak-text-input/KeycloakTextInput";
import { ViewHeader } from "../components/view-header/ViewHeader";
import { useServerInfo } from "../context/server-info/ServerInfoProvider";
import { useFetch } from "../utils/useFetch";
import { useParams } from "../utils/useParams";
import { toAddExecutor } from "./routes/AddExecutor";
import { toClientPolicies } from "./routes/ClientPolicies";
import { ClientProfileParams, toClientProfile } from "./routes/ClientProfile";
import { toExecutor } from "./routes/Executor";

import "./realm-settings-section.css";

type ClientProfileForm = Required<ClientProfileRepresentation>;

const defaultValues: ClientProfileForm = {
  name: "",
  description: "",
  executors: [],
};

export default function ClientProfileForm() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const {
    handleSubmit,
    setValue,
    getValues,
    register,
    formState: { isDirty, errors },
    control,
  } = useForm<ClientProfileForm>({
    defaultValues,
    mode: "onChange",
  });

  const { fields: profileExecutors, remove } = useFieldArray({
    name: "executors",
    control,
  });

  const { addAlert, addError } = useAlerts();
  const [profiles, setProfiles] = useState<ClientProfilesRepresentation>();
  const [isGlobalProfile, setIsGlobalProfile] = useState(false);
  const { realm, profileName } = useParams<ClientProfileParams>();
  const serverInfo = useServerInfo();
  const executorTypes = useMemo(
    () =>
      serverInfo.componentTypes?.[
        "org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider"
      ],
    [],
  );
  const [executorToDelete, setExecutorToDelete] = useState<{
    idx: number;
    name: string;
  }>();
  const editMode = profileName ? true : false;
  const [key, setKey] = useState(0);
  const reload = () => setKey(key + 1);

  useFetch(
    () =>
      adminClient.clientPolicies.listProfiles({ includeGlobalProfiles: true }),
    (profiles) => {
      setProfiles({
        globalProfiles: profiles.globalProfiles,
        profiles: profiles.profiles?.filter((p) => p.name !== profileName),
      });
      const globalProfile = profiles.globalProfiles?.find(
        (p) => p.name === profileName,
      );
      const profile = profiles.profiles?.find((p) => p.name === profileName);
      setIsGlobalProfile(globalProfile !== undefined);
      setValue("name", globalProfile?.name ?? profile?.name ?? "");
      setValue(
        "description",
        globalProfile?.description ?? profile?.description ?? "",
      );
      setValue(
        "executors",
        globalProfile?.executors ?? profile?.executors ?? [],
      );
    },
    [key],
  );

  const save = async (form: ClientProfileForm) => {
    const updatedProfiles = form;

    try {
      await adminClient.clientPolicies.createProfiles({
        ...profiles,
        profiles: [...(profiles?.profiles || []), updatedProfiles],
      });

      addAlert(
        editMode
          ? t("updateClientProfileSuccess")
          : t("createClientProfileSuccess"),
        AlertVariant.success,
      );

      navigate(toClientProfile({ realm, profileName: form.name }));
    } catch (error) {
      addError(
        editMode ? "updateClientProfileError" : "createClientProfileError",
        error,
      );
    }
  };

  const [toggleDeleteDialog, DeleteConfirm] = useConfirmDialog({
    titleKey: executorToDelete?.name!
      ? t("deleteExecutorProfileConfirmTitle")
      : t("deleteClientProfileConfirmTitle"),
    messageKey: executorToDelete?.name!
      ? t("deleteExecutorProfileConfirm", {
          executorName: executorToDelete.name!,
        })
      : t("deleteClientProfileConfirm", {
          profileName,
        }),
    continueButtonLabel: t("delete"),
    continueButtonVariant: ButtonVariant.danger,

    onConfirm: async () => {
      if (executorToDelete?.name!) {
        remove(executorToDelete.idx);
        try {
          await adminClient.clientPolicies.createProfiles({
            ...profiles,
            profiles: [...(profiles!.profiles || []), getValues()],
          });
          addAlert(t("deleteExecutorSuccess"), AlertVariant.success);
          navigate(toClientProfile({ realm, profileName }));
        } catch (error) {
          addError(t("deleteExecutorError"), error);
        }
      } else {
        try {
          await adminClient.clientPolicies.createProfiles(profiles);
          addAlert(t("deleteClientSuccess"), AlertVariant.success);
          navigate(toClientPolicies({ realm, tab: "profiles" }));
        } catch (error) {
          addError(t("deleteClientError"), error);
        }
      }
    },
  });

  if (!profiles) {
    return <KeycloakSpinner />;
  }

  return (
    <>
      <DeleteConfirm />
      <ViewHeader
        titleKey={editMode ? profileName : t("newClientProfile")}
        badges={[
          {
            id: "global-client-profile-badge",
            text: isGlobalProfile ? (
              <Label color="blue">{t("global")}</Label>
            ) : (
              ""
            ),
          },
        ]}
        divider
        dropdownItems={
          editMode && !isGlobalProfile
            ? [
                <DropdownItem
                  key="delete"
                  value="delete"
                  onClick={toggleDeleteDialog}
                  data-testid="deleteClientProfileDropdown"
                >
                  {t("deleteClientProfile")}
                </DropdownItem>,
              ]
            : undefined
        }
      />
      <PageSection variant="light">
        <FormAccess isHorizontal role="view-realm" className="pf-u-mt-lg">
          <FormGroup
            label={t("newClientProfileName")}
            fieldId="kc-name"
            helperText={t("createClientProfileNameHelperText")}
            isRequired
            helperTextInvalid={t("required")}
            validated={
              errors.name ? ValidatedOptions.error : ValidatedOptions.default
            }
          >
            <KeycloakTextInput
              id="kc-name"
              data-testid="client-profile-name"
              isReadOnly={isGlobalProfile}
              {...register("name", { required: true })}
            />
          </FormGroup>
          <FormGroup label={t("description")} fieldId="kc-description">
            <KeycloakTextArea
              id="kc-description"
              data-testid="client-profile-description"
              isReadOnly={isGlobalProfile}
              {...register("description")}
            />
          </FormGroup>
          <ActionGroup>
            {!isGlobalProfile && (
              <Button
                variant="primary"
                onClick={() => handleSubmit(save)()}
                data-testid="saveCreateProfile"
                isDisabled={!isDirty}
              >
                {t("save")}
              </Button>
            )}
            {editMode && !isGlobalProfile && (
              <Button
                id={"reloadProfile"}
                variant="link"
                data-testid={"reloadProfile"}
                isDisabled={!isDirty}
                onClick={reload}
              >
                {t("reload")}
              </Button>
            )}
            {!editMode && !isGlobalProfile && (
              <Button
                id={"cancelCreateProfile"}
                variant="link"
                component={(props) => (
                  <Link
                    {...props}
                    to={toClientPolicies({ realm, tab: "profiles" })}
                  />
                )}
                data-testid={"cancelCreateProfile"}
              >
                {t("cancel")}
              </Button>
            )}
          </ActionGroup>
          {editMode && (
            <>
              <Flex>
                <FlexItem>
                  <Text className="kc-executors" component={TextVariants.h1}>
                    {t("executors")}
                    <HelpItem
                      helpText={t("executorsHelpText")}
                      fieldLabelId="executors"
                    />
                  </Text>
                </FlexItem>
                {!isGlobalProfile && (
                  <FlexItem align={{ default: "alignRight" }}>
                    <Button
                      id="addExecutor"
                      component={(props) => (
                        <Link
                          {...props}
                          to={toAddExecutor({
                            realm,
                            profileName,
                          })}
                        />
                      )}
                      variant="link"
                      className="kc-addExecutor"
                      data-testid="addExecutor"
                      icon={<PlusCircleIcon />}
                    >
                      {t("addExecutor")}
                    </Button>
                  </FlexItem>
                )}
              </Flex>
              {profileExecutors.length > 0 && (
                <>
                  <DataList aria-label={t("executors")} isCompact>
                    {profileExecutors.map((executor, idx) => (
                      <DataListItem
                        aria-labelledby={"executors-list-item"}
                        key={executor.executor}
                        id={executor.executor}
                      >
                        <DataListItemRow data-testid="executors-list-row">
                          <DataListItemCells
                            dataListCells={[
                              <DataListCell
                                key="executor"
                                data-testid="executor-type"
                              >
                                {executor.configuration ? (
                                  <Button
                                    component={(props) => (
                                      <Link
                                        {...props}
                                        to={toExecutor({
                                          realm,
                                          profileName,
                                          executorName: executor.executor!,
                                        })}
                                      />
                                    )}
                                    variant="link"
                                    data-testid="editExecutor"
                                  >
                                    {executor.executor}
                                  </Button>
                                ) : (
                                  <span className="kc-unclickable-executor">
                                    {executor.executor}
                                  </span>
                                )}
                                {executorTypes
                                  ?.filter(
                                    (type) => type.id === executor.executor,
                                  )
                                  .map((type) => (
                                    <Fragment key={type.id}>
                                      <HelpItem
                                        key={type.id}
                                        helpText={type.helpText}
                                        fieldLabelId="executorTypeTextHelpText"
                                      />
                                      {!isGlobalProfile && (
                                        <Button
                                          variant="link"
                                          isInline
                                          icon={
                                            <TrashIcon
                                              key={`executorType-trash-icon-${type.id}`}
                                              className="kc-executor-trash-icon"
                                              data-testid="deleteExecutor"
                                            />
                                          }
                                          onClick={() => {
                                            toggleDeleteDialog();
                                            setExecutorToDelete({
                                              idx: idx,
                                              name: type.id,
                                            });
                                          }}
                                          aria-label={t("remove")}
                                        />
                                      )}
                                    </Fragment>
                                  ))}
                              </DataListCell>,
                            ]}
                          />
                        </DataListItemRow>
                      </DataListItem>
                    ))}
                  </DataList>
                  {isGlobalProfile && (
                    <Button
                      id="backToClientPolicies"
                      component={(props) => (
                        <Link
                          {...props}
                          to={toClientPolicies({ realm, tab: "profiles" })}
                        />
                      )}
                      variant="primary"
                      className="kc-backToPolicies"
                      data-testid="backToClientPolicies"
                    >
                      {t("back")}
                    </Button>
                  )}
                </>
              )}
              {profileExecutors.length === 0 && (
                <>
                  <Divider />
                  <Text
                    className="kc-emptyExecutors"
                    component={TextVariants.h2}
                  >
                    {t("emptyExecutors")}
                  </Text>
                </>
              )}
            </>
          )}
        </FormAccess>
      </PageSection>
    </>
  );
}

import type ClientRepresentation from "@keycloak/keycloak-admin-client/lib/defs/clientRepresentation";
import type EvaluationResultRepresentation from "@keycloak/keycloak-admin-client/lib/defs/evaluationResultRepresentation";
import PolicyEvaluationResponse from "@keycloak/keycloak-admin-client/lib/defs/policyEvaluationResponse";
import type ResourceEvaluation from "@keycloak/keycloak-admin-client/lib/defs/resourceEvaluation";
import {
  ListEmptyState,
  SelectControl,
  useAlerts,
} from "@keycloak/keycloak-ui-shared";
import {
  ActionGroup,
  Alert,
  AlertActionCloseButton,
  Button,
  PageSection,
  Panel,
  PanelHeader,
  PanelMainBody,
  Split,
  SplitItem,
  Title,
} from "@patternfly/react-core";
import { useMemo, useState } from "react";
import { FormProvider, useForm, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { useAdminClient } from "../../admin-client";
import { UserSelect } from "../../components/users/UserSelect";
import { ClientSelect } from "../../components/client/ClientSelect";
import { GroupSelect } from "../resource-types/GroupSelect";
import { FormAccess } from "../../components/form/FormAccess";
import { useAccess } from "../../context/access/Access";
import { ForbiddenSection } from "../../ForbiddenSection";
import { BellIcon } from "@patternfly/react-icons";
import { useRealm } from "../../context/realm-context/RealmContext";
import { PermissionEvaluationResult } from "./PermissionEvaluationResult";
import useSortedResourceTypes from "../../utils/useSortedResourceTypes";

interface EvaluateFormInputs
  extends Omit<ResourceEvaluation, "context" | "resources"> {
  authScopes: string[];
  user: string[];
  clients: string[];
  groups: string[];
  users: string[];
  resourceType?: string;
}

type Props = {
  client: ClientRepresentation;
  save: () => void;
} & EvaluationResultRepresentation;

const COMPONENTS: Record<string, React.ElementType> = {
  users: UserSelect,
  clients: ClientSelect,
  groups: GroupSelect,
};

export const PermissionsEvaluationTab = (props: Props) => {
  const { hasAccess } = useAccess();

  if (!hasAccess("view-users")) {
    return <ForbiddenSection permissionNeeded="view-users" />;
  }

  return <PermissionEvaluateContent {...props} />;
};

const PermissionEvaluateContent = ({ client }: Props) => {
  const { t } = useTranslation();
  const { adminClient } = useAdminClient();
  const realm = useRealm();
  const { addError } = useAlerts();
  const form = useForm<EvaluateFormInputs>({
    mode: "onChange",
    defaultValues: {
      user: [],
      resourceType: "",
      authScopes: [],
    },
  });
  const { control, getValues, reset, trigger } = form;
  const [evaluateResult, setEvaluateResult] =
    useState<PolicyEvaluationResponse>();
  const [isAlertOpened, setIsAlertOpened] = useState(true);
  const [isEvaluated, setIsEvaluated] = useState(false);
  const resourceTypes = useSortedResourceTypes({ clientId: client.id! });

  const selectedResourceType = useWatch({
    control: control,
    name: "resourceType",
    defaultValue: "",
  });

  const authScopes = useMemo(() => {
    const resource = resourceTypes.find((r) => r.type === selectedResourceType);
    return resource?.scopes || [];
  }, [selectedResourceType, resourceTypes]);

  const ResourceTypeComponent =
    COMPONENTS[selectedResourceType?.toLowerCase() || ""];

  const evaluate = async () => {
    if (!(await trigger())) {
      return;
    }

    const formValues = getValues();
    const getResourceName = (resourceType: string) => {
      switch (resourceType) {
        case "Groups":
          return formValues.groups?.[0];
        case "Users":
          return formValues.users?.[0];
        case "Clients":
          return formValues.clients?.[0];
        default:
          return undefined;
      }
    };

    const resourceName = getResourceName(formValues.resourceType!);

    const resEval: ResourceEvaluation = {
      roleIds: formValues.roleIds ?? [],
      userId: formValues.user![0],
      resources: [
        {
          name: resourceName,
          scopes: formValues.authScopes!.map((scope) => ({ name: scope })),
        },
      ],
      entitlements: false,
      context: {
        attributes: {},
      },
    };

    try {
      const evaluation = await adminClient.clients.evaluateResource(
        { id: client.id!, realm: realm.realm },
        resEval,
      );

      setEvaluateResult(evaluation);
      setIsEvaluated(true);
    } catch (error) {
      addError("evaluateError", error);
    }
  };

  return (
    <PageSection>
      <Split hasGutter>
        <SplitItem>
          <FormProvider {...form}>
            <Panel>
              <PanelMainBody style={{ width: "50rem" }}>
                <FormAccess isHorizontal role="view-clients">
                  {isAlertOpened && (
                    <Alert
                      variant="info"
                      isInline
                      title={t("permissionsEvaluationInstructions")}
                      component="p"
                      actionClose={
                        <AlertActionCloseButton
                          onClose={() => setIsAlertOpened(false)}
                        />
                      }
                    />
                  )}
                  <UserSelect
                    name="user"
                    label={t("user")}
                    helpText={t("selectUser")}
                    defaultValue={[]}
                    variant="typeahead"
                    isRequired
                  />
                  <SelectControl
                    name="resourceType"
                    label={t("resourceType")}
                    labelIcon={t("resourceTypeSelectHelp")}
                    variant="single"
                    controller={{
                      defaultValue: resourceTypes.length
                        ? resourceTypes[0]?.type
                        : "",
                      rules: { required: true },
                    }}
                    options={resourceTypes.map((resource) => resource.type!)}
                  />
                  {ResourceTypeComponent && (
                    <ResourceTypeComponent
                      name={selectedResourceType?.toLowerCase()}
                      label={t(`${selectedResourceType}`)}
                      helpText={t(`select${selectedResourceType}`)}
                      defaultValue={[]}
                      variant="typeahead"
                      isRequired
                    />
                  )}
                  <SelectControl
                    name="authScopes"
                    label={t("authScope")}
                    labelIcon={t("authScopeSelectHelp")}
                    controller={{ defaultValue: [] }}
                    variant="single"
                    options={authScopes}
                  />
                </FormAccess>
              </PanelMainBody>
            </Panel>
            <ActionGroup>
              <Button
                data-testid="permission-eval"
                id="permission-eval"
                className="pf-v5-u-mr-md"
                isDisabled={!form.formState.isValid}
                onClick={() => evaluate()}
              >
                {t("evaluate")}
              </Button>
              <Button
                data-testid="permission-eval-revert"
                id="permission-eval-revert"
                className="pf-v5-u-mr-md"
                variant="link"
                onClick={() => {
                  reset();
                  setEvaluateResult({});
                  setIsEvaluated(false);
                }}
              >
                {t("revert")}
              </Button>
            </ActionGroup>
          </FormProvider>
        </SplitItem>
        <SplitItem>
          <Panel>
            <PanelHeader>
              <Title headingLevel="h1" size="md">
                {t("permissionEvaluationPreview")}
              </Title>
            </PanelHeader>
            <PanelMainBody>
              {!isEvaluated ? (
                <ListEmptyState
                  icon={BellIcon}
                  message={t("noPermissionsEvaluationResults")}
                  instructions={t("noPermissionsEvaluationResultsInstructions")}
                />
              ) : (
                <PermissionEvaluationResult evaluateResult={evaluateResult!} />
              )}
            </PanelMainBody>
          </Panel>
        </SplitItem>
      </Split>
    </PageSection>
  );
};

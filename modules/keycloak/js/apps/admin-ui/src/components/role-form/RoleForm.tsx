import { ActionGroup, Button, PageSection } from "@patternfly/react-core";
import { SubmitHandler, useFormContext, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Link, To } from "react-router-dom";
import { TextAreaControl, TextControl } from "ui-shared";

import { FormAccess } from "../form/FormAccess";
import { AttributeForm } from "../key-value-form/AttributeForm";
import { ViewHeader } from "../view-header/ViewHeader";

export type RoleFormProps = {
  onSubmit: SubmitHandler<AttributeForm>;
  cancelLink: To;
  role: "manage-realm" | "manage-clients";
  editMode: boolean;
};

export const RoleForm = ({
  onSubmit,
  cancelLink,
  role,
  editMode,
}: RoleFormProps) => {
  const { t } = useTranslation();
  const { control, handleSubmit } = useFormContext<AttributeForm>();

  const roleName = useWatch({
    control,
    defaultValue: undefined,
    name: "name",
  });

  return (
    <>
      {!editMode && <ViewHeader titleKey={t("createRole")} />}
      <PageSection variant="light">
        <FormAccess
          isHorizontal
          onSubmit={handleSubmit(onSubmit)}
          role={role}
          className="pf-u-mt-lg"
        >
          <TextControl
            name="name"
            label={t("roleName")}
            rules={{
              required: !editMode ? t("required") : undefined,
              validate(value) {
                if (!value?.trim()) {
                  return t("required");
                }
              },
            }}
            readOnly={editMode}
          />
          <TextAreaControl
            name="description"
            label={t("description")}
            rules={{
              maxLength: {
                value: 255,
                message: t("maxLength", { length: 255 }),
              },
            }}
            isDisabled={roleName?.includes("default-roles") ?? false}
          />
          <ActionGroup>
            <Button data-testid="save" type="submit" variant="primary">
              {t("save")}
            </Button>
            <Button
              data-testid="cancel"
              variant="link"
              component={(props) => <Link {...props} to={cancelLink} />}
            >
              {t("cancel")}
            </Button>
          </ActionGroup>
        </FormAccess>
      </PageSection>
    </>
  );
};

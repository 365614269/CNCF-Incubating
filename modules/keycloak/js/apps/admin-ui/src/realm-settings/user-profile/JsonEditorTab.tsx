import { useAlerts } from "@keycloak/keycloak-ui-shared";
import { ActionGroup, Button, Form, PageSection } from "@patternfly/react-core";
import CodeEditor from "@uiw/react-textarea-code-editor";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { prettyPrintJSON } from "../../util";
import { useUserProfile } from "./UserProfileContext";

export const JsonEditorTab = () => {
  const { config, save, isSaving } = useUserProfile();
  const { t } = useTranslation();
  const { addError } = useAlerts();
  const [code, setCode] = useState(prettyPrintJSON(config));

  function resetCode() {
    setCode(config ? prettyPrintJSON(config) : "");
  }

  async function handleSave() {
    const value = code;

    if (!value) {
      return;
    }

    try {
      await save(JSON.parse(value));
    } catch (error) {
      addError("invalidJsonError", error);
      return;
    }
  }

  return (
    <PageSection variant="light">
      <CodeEditor
        language="json"
        value={code}
        style={{ height: "30rem", overflow: "scroll" }}
        onChange={(event) => setCode(event.target.value ?? "")}
      />
      <Form>
        <ActionGroup>
          <Button
            data-testid="save"
            variant="primary"
            onClick={handleSave}
            isDisabled={isSaving}
          >
            {t("save")}
          </Button>
          <Button variant="link" onClick={resetCode} isDisabled={isSaving}>
            {t("revert")}
          </Button>
        </ActionGroup>
      </Form>
    </PageSection>
  );
};

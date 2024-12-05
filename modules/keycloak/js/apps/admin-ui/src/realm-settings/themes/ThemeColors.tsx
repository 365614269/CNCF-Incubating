import RealmRepresentation from "@keycloak/keycloak-admin-client/lib/defs/realmRepresentation";
import { TextControl } from "@keycloak/keycloak-ui-shared";
import {
  Alert,
  Button,
  Flex,
  FlexItem,
  FormGroup,
  InputGroup,
  InputGroupItem,
  PageSection,
  Text,
  TextContent,
  TextInputProps,
} from "@patternfly/react-core";
import { useEffect, useMemo } from "react";
import {
  FormProvider,
  useForm,
  useFormContext,
  useWatch,
} from "react-hook-form";
import { useTranslation } from "react-i18next";
import { FixedButtonsGroup } from "../../components/form/FixedButtonGroup";
import { FormAccess } from "../../components/form/FormAccess";
import { ImageUpload } from "./ImageUpload";
import { usePreviewLogo } from "./LogoContext";
import { darkTheme, lightTheme } from "./PatternflyVars";
import { PreviewWindow } from "./PreviewWindow";
import { ThemeRealmRepresentation } from "./ThemesTab";

type ThemeType = "light" | "dark";

type ColorControlProps = TextInputProps & {
  name: string;
  label: string;
  color: string;
};

const ColorControl = ({ name, color, label, ...props }: ColorControlProps) => {
  const { t } = useTranslation();
  const { control, setValue } = useFormContext();
  const currentValue = useWatch({
    control,
    name,
  });
  return (
    <InputGroup>
      <InputGroupItem isFill>
        <TextControl {...props} name={name} label={t(label)} />
      </InputGroupItem>
      <input
        type="color"
        value={currentValue || color}
        onChange={(e) => setValue(name, e.target.value)}
      />
    </InputGroup>
  );
};

const switchTheme = (theme: ThemeType) => {
  if (theme === "light") {
    document
      .querySelector('meta[name="color-scheme"]')!
      .setAttribute("content", "light");
    document.documentElement.classList.remove("pf-v5-theme-dark");
  } else {
    document.documentElement.classList.add("pf-v5-theme-dark");
  }
};

type ThemeColorsProps = {
  realm: RealmRepresentation;
  save: (realm: ThemeRealmRepresentation) => void;
  theme: "light" | "dark";
};

export const ThemeColors = ({ realm, save, theme }: ThemeColorsProps) => {
  const { t } = useTranslation();
  const form = useForm();
  const { handleSubmit, watch } = form;
  const style = watch();
  const contextLogo = usePreviewLogo();

  const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
  const mapping = useMemo(
    () => (theme === "light" ? lightTheme() : darkTheme()),
    [],
  );

  const reset = () => {
    form.reset({
      [theme]: mapping.reduce(
        (acc, m) => ({
          ...acc,
          [m.variable!]: m.defaultValue,
        }),
        {},
      ),
    });
  };

  const setupForm = () => {
    const values = JSON.parse(realm.attributes?.style || "{}");
    if (values[theme]) {
      form.reset(values);
    } else {
      reset();
    }
  };

  const convert = (values: Record<string, File | string>) => {
    const styles = JSON.parse(realm.attributes?.style || "{}");
    save({
      ...realm,
      logo: values.logo as File,
      bgimage: values.bgimage as File,
      attributes: {
        ...realm.attributes,
        style: JSON.stringify({
          ...styles,
          ...values,
        }),
      },
    });
  };

  useEffect(() => {
    setupForm();
    switchTheme(theme);
    return () => {
      switchTheme(mediaQuery.matches ? "dark" : "light");
    };
  }, [realm]);

  return (
    <PageSection variant="light">
      <TextContent className="pf-v5-u-mb-lg">
        <Text>{t("themeColorInfo")}</Text>
      </TextContent>
      {mediaQuery.matches && theme === "light" && (
        <Alert variant="info" isInline title={t("themePreviewInfo")} />
      )}
      <Flex className="pf-v5-u-pt-lg">
        <FlexItem>
          <FormAccess isHorizontal role="manage-realm">
            <FormProvider {...form}>
              <FormGroup label={t("logo")}>
                <ImageUpload
                  name="logo"
                  onChange={(logo) => contextLogo?.setLogo(logo)}
                />
              </FormGroup>
              <FormGroup label={t("backgroundImage")}>
                <ImageUpload name="bgimage" />
              </FormGroup>
              {mapping.map((m) => (
                <ColorControl
                  key={m.name}
                  color={m.defaultValue!}
                  name={`${theme}.${m.variable!}`}
                  label={m.name}
                />
              ))}
            </FormProvider>
          </FormAccess>
        </FlexItem>
        <FlexItem grow={{ default: "grow" }} style={{ zIndex: 0 }}>
          <PreviewWindow cssVars={style?.[theme] || {}} />
        </FlexItem>
      </Flex>
      <FixedButtonsGroup
        name="colors"
        saveText={t("downloadThemeJar")}
        save={handleSubmit(convert)}
        reset={setupForm}
      >
        <Button type="button" variant="link" onClick={reset}>
          {t("defaults")}
        </Button>
      </FixedButtonsGroup>
    </PageSection>
  );
};

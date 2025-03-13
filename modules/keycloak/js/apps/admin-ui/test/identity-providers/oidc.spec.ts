import { test } from "@playwright/test";
import { v4 as uuid } from "uuid";
import adminClient from "../utils/AdminClient";
import { switchOff, switchOn } from "../utils/form";
import { login } from "../utils/login";
import { assertNotificationMessage } from "../utils/masthead";
import { goToIdentityProviders } from "../utils/sidebar";
import { clickTableRowItem } from "../utils/table";
import {
  addMapper,
  assertAuthorizationUrl,
  assertInvalidUrlNotification,
  assertJwksUrlExists,
  assertOnMappingPage,
  assertPkceMethodExists,
  clickCancelMapper,
  clickRevertButton,
  clickSaveButton,
  clickSaveMapper,
  createOIDCProvider,
  goToMappersTab,
  setUrl,
} from "./main";

test.describe("OIDC identity provider test", () => {
  const oidcProviderName = "oidc";
  const secret = "123";

  test.beforeEach(async ({ page }) => {
    await login(page);
    await goToIdentityProviders(page);
  });

  test.afterAll(() => adminClient.deleteIdentityProvider(oidcProviderName));

  test("should create an OIDC provider using discovery url", async ({
    page,
  }) => {
    await createOIDCProvider(page, oidcProviderName, secret);
    await assertNotificationMessage(
      page,
      "Identity provider successfully created",
    );
    await assertAuthorizationUrl(page);

    await setUrl(page, "authorization", "invalid");
    await clickSaveButton(page);
    await assertInvalidUrlNotification(page, "authorization");
    await clickRevertButton(page);

    await setUrl(page, "token", "invalid");
    await clickSaveButton(page);
    await assertInvalidUrlNotification(page, "token");
    await clickRevertButton(page);

    await assertJwksUrlExists(page);
    await switchOff(page, "#config\\.useJwksUrl");
    await assertJwksUrlExists(page, false);

    await assertPkceMethodExists(page, false);
    await switchOn(page, "#config\\.pkceEnabled");
    await assertPkceMethodExists(page);

    await clickSaveButton(page);
    await assertNotificationMessage(page, "Provider successfully updated");
  });
});

test.describe("Edit OIDC Provider", () => {
  const oidcProviderName = "OpenID Connect v1.0";
  const alias = `edit-oidc-${uuid()}`;

  test.beforeEach(async ({ page }) => {
    await adminClient.createIdentityProvider(oidcProviderName, alias);
    await login(page);
    await goToIdentityProviders(page);
    await clickTableRowItem(page, oidcProviderName);
  });

  test.afterEach(() => adminClient.deleteIdentityProvider(alias));

  test("should add OIDC mapper of type Attribute Importer", async ({
    page,
  }) => {
    await goToMappersTab(page);
    await addMapper(page, "oidc-user-attribute", "OIDC Attribute Importer");
    await clickSaveMapper(page);
    await assertNotificationMessage(page, "Mapper created successfully.");
  });

  test("should add OIDC mapper of type Claim To Role", async ({ page }) => {
    await goToMappersTab(page);
    await addMapper(page, "oidc-role", "OIDC Claim to Role");
    await clickSaveMapper(page);
    await assertNotificationMessage(page, "Mapper created successfully.");
  });

  test("should cancel the addition of the OIDC mapper", async ({ page }) => {
    await goToMappersTab(page);
    await addMapper(page, "oidc-role", "OIDC Claim to Role");
    await clickCancelMapper(page);
    await assertOnMappingPage(page);
  });
});

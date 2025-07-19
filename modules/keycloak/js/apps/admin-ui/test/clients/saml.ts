import { Locator, Page, expect } from "@playwright/test";
import {
  assertSelectValue,
  selectItem,
  switchOff,
  switchOn,
} from "../utils/form";

function getTermsOfServiceUrl(page: Page) {
  return page.getByTestId("attributes.tosUri");
}

function getKeyForEncryptionAlgorithmInput(page: Page) {
  return page.locator("#attributes\\.saml🍺encryption🍺algorithm");
}

function getKeyForEncryptionKeyAlgorithmInput(page: Page) {
  return page.locator("#attributes\\.saml🍺encryption🍺keyAlgorithm");
}

function getKeyForEncryptionDigestMethodInput(page: Page) {
  return page.locator("#attributes\\.saml🍺encryption🍺digestMethod");
}

function getKeyForEncryptionMaskGenerationFunctionInput(page: Page) {
  return page.locator("#attributes\\.saml🍺encryption🍺maskGenerationFunction");
}

export async function setTermsOfServiceUrl(page: Page, url: string) {
  await getTermsOfServiceUrl(page).fill(url);
}

export async function saveFineGrain(page: Page) {
  await page.getByTestId("fineGrainSave").click();
}

export async function revertFineGrain(page: Page) {
  await page.getByTestId("fineGrainRevert").click();
}

export async function assertTermsOfServiceUrl(page: Page, expectedUrl: string) {
  await expect(getTermsOfServiceUrl(page)).toHaveValue(expectedUrl);
}

export async function assertSamlClientDetails(page: Page) {
  await expect(page.getByTestId("jump-link-saml-capabilities")).toBeVisible();
}

export async function clickPostBinding(page: Page) {
  await switchOff(page, "#attributes\\.saml🍺force🍺post🍺binding");
}

export async function saveSamlSettings(page: Page) {
  await page.getByTestId("settings-save").click();
}

export async function goToKeysTab(page: Page) {
  await page.getByTestId("keysTab").click();
}

export async function goToClientSettingsTab(page: Page) {
  await page.getByTestId("clientSettingsTab").click();
}

export async function clickClientSignature(page: Page) {
  await switchOff(page, "#clientSignature");
}

export async function assertCertificate(page: Page, exists = true) {
  await expect(page.getByTestId("certificate")).toHaveCount(exists ? 0 : 1);
}

export async function clickEncryptionAssertions(page: Page) {
  await switchOn(page, "#encryptAssertions");
}

export async function clickOffEncryptionAssertions(page: Page) {
  await switchOff(page, "#encryptAssertions");
}

export async function clickGenerate(page: Page) {
  await page.getByTestId("generate").click();
}

export async function assertNameIdFormatDropdown(page: Page) {
  const items = ["username", "email", "transient", "persistent"];
  for (const item of items) {
    await selectItem(
      page,
      page.locator("#attributes\\.saml_name_id_format"),
      item,
    );
    await expect(page.locator("#attributes\\.saml_name_id_format")).toHaveText(
      item,
    );
  }
}

export async function selectEncryptionAlgorithmInput(
  page: Page,
  value: string,
) {
  await selectItem(page, getKeyForEncryptionAlgorithmInput(page), value);
}

export async function selectEncryptionKeyAlgorithmInput(
  page: Page,
  value: string,
) {
  await selectItem(page, getKeyForEncryptionKeyAlgorithmInput(page), value);
}

export async function selectEncryptionDigestMethodInput(
  page: Page,
  value: string,
) {
  await selectItem(page, getKeyForEncryptionDigestMethodInput(page), value);
}

export async function selectEncryptionMaskGenerationFunctionInput(
  page: Page,
  value: string,
) {
  await selectItem(
    page,
    getKeyForEncryptionMaskGenerationFunctionInput(page),
    value,
  );
}

export async function assertEncryptionAlgorithm(page: Page, value: string) {
  await assertSelectValue(getKeyForEncryptionAlgorithmInput(page), value);
}

export async function assertEncryptionKeyAlgorithm(page: Page, value: string) {
  await assertSelectValue(getKeyForEncryptionKeyAlgorithmInput(page), value);
}

export async function assertEncryptionDigestMethod(page: Page, value: string) {
  await assertSelectValue(getKeyForEncryptionDigestMethodInput(page), value);
}

export async function assertEncryptionMaskGenerationFunction(
  page: Page,
  value: string,
) {
  await assertSelectValue(
    getKeyForEncryptionMaskGenerationFunctionInput(page),
    value,
  );
}

async function assertInputVisible(locator: Locator, visible: boolean) {
  if (visible) {
    await expect(locator).toBeVisible();
  } else {
    await expect(locator).toBeHidden();
  }
}

export async function assertEncryptionAlgorithmInputVisible(
  page: Page,
  visible: boolean,
) {
  await assertInputVisible(getKeyForEncryptionAlgorithmInput(page), visible);
}

export async function assertEncryptionKeyAlgorithmInputVisible(
  page: Page,
  visible: boolean,
) {
  await assertInputVisible(getKeyForEncryptionKeyAlgorithmInput(page), visible);
}

export async function assertEncryptionDigestMethodInputVisible(
  page: Page,
  visible: boolean,
) {
  await assertInputVisible(getKeyForEncryptionDigestMethodInput(page), visible);
}

export async function assertEncryptionMaskGenerationFunctionInputVisible(
  page: Page,
  visible: boolean,
) {
  await assertInputVisible(
    getKeyForEncryptionMaskGenerationFunctionInput(page),
    visible,
  );
}

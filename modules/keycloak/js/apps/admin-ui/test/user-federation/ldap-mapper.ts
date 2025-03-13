import ComponentRepresentation from "@keycloak/keycloak-admin-client/lib/defs/componentRepresentation";
import { Page } from "@playwright/test";
import {
  changeRoleTypeFilter,
  confirmModalAssign,
  pickRole,
} from "../utils/roles";

export async function goToMapperTab(page: Page) {
  await page.getByTestId("ldap-mappers-tab").click();
}

export async function clickAddMapper(page: Page) {
  await page.getByTestId("add-mapper-btn").click();
}

export async function fillHardwareAttributeMapper(
  page: Page,
  data: ComponentRepresentation,
) {
  await page.getByTestId("name").fill(data.name || "");
  if (data.config?.["user.model.attribute"])
    await page
      .getByTestId("config.user🍺model🍺attribute")
      .fill(data.config?.["user.model.attribute"][0] || "");

  if (data.config?.["attribute.value"])
    await page
      .getByTestId("attribute.value")
      .fill(data.config?.["attribute.value"][0] || "");

  if (data.config?.group)
    await page.getByTestId("group").fill(data.config?.group[0] || "");

  if (data.config?.["ldap.attribute.name"])
    await page
      .getByTestId("ldap.attribute.name")
      .fill(data.config?.["ldap.attribute.name"][0] || "");

  if (data.config?.["ldap.attribute.value"])
    await page
      .getByTestId("ldap.attribute.value")
      .fill(data.config?.["ldap.attribute.value"][0] || "");

  if (data.config?.role) {
    await page.getByTestId("add-roles").click();
    await changeRoleTypeFilter(page, "roles");
    await pickRole(page, data.config.role[0], true);
    await confirmModalAssign(page);
  }

  if (data.config?.roleDn)
    await page.getByTestId("roles.dn").fill(data.config?.roleDn[0] || "");
}

export async function saveMapper(page: Page) {
  await page.getByTestId("ldap-mapper-save").click();
}

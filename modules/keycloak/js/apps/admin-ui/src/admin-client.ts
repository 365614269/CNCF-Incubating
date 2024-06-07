import KeycloakAdminClient from "@keycloak/keycloak-admin-client";
import {
  createNamedContext,
  useRequiredContext,
} from "@keycloak/keycloak-ui-shared";
import type Keycloak from "keycloak-js";

import type { Environment } from "./environment";

export type AdminClientProps = {
  keycloak: Keycloak;
  adminClient: KeycloakAdminClient;
};

export const AdminClientContext = createNamedContext<
  AdminClientProps | undefined
>("AdminClientContext", undefined);

export const useAdminClient = () => useRequiredContext(AdminClientContext);

export async function initAdminClient(
  keycloak: Keycloak,
  environment: Environment,
) {
  const adminClient = new KeycloakAdminClient();

  adminClient.setConfig({ realmName: environment.realm });
  adminClient.baseUrl = environment.authServerUrl;
  adminClient.registerTokenProvider({
    async getAccessToken() {
      try {
        await keycloak.updateToken(5);
      } catch (error) {
        keycloak.login();
      }

      return keycloak.token;
    },
  });

  return adminClient;
}

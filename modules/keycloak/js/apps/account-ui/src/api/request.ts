import { Environment } from "../environment";
import Keycloak from "keycloak-js";
import { CONTENT_TYPE_HEADER, CONTENT_TYPE_JSON } from "./constants";
import { joinPath } from "../utils/joinPath";
import { KeycloakContext } from "../root/KeycloakContext";

export type RequestOptions = {
  signal?: AbortSignal;
  getAccessToken?: () => Promise<string | undefined>;
  method?: "POST" | "PUT" | "DELETE";
  searchParams?: Record<string, string>;
  body?: unknown;
};

async function _request(
  url: URL,
  { signal, getAccessToken, method, searchParams, body }: RequestOptions = {},
): Promise<Response> {
  if (searchParams) {
    Object.entries(searchParams).forEach(([key, value]) =>
      url.searchParams.set(key, value),
    );
  }

  return fetch(url, {
    signal,
    method,
    body: body ? JSON.stringify(body) : undefined,
    headers: {
      [CONTENT_TYPE_HEADER]: CONTENT_TYPE_JSON,
      authorization: `Bearer ${await getAccessToken?.()}`,
    },
  });
}

export async function request(
  path: string,
  { environment, keycloak }: KeycloakContext,
  opts: RequestOptions = {},
) {
  return _request(url(environment, path), {
    ...opts,
    getAccessToken: token(keycloak),
  });
}

export const url = (environment: Environment, path: string) =>
  new URL(
    joinPath(environment.authUrl, "realms", environment.realm, "account", path),
  );

export const token = (keycloak: Keycloak) =>
  async function getAccessToken() {
    try {
      await keycloak.updateToken(5);
    } catch (error) {
      await keycloak.login();
    }

    return keycloak.token;
  };

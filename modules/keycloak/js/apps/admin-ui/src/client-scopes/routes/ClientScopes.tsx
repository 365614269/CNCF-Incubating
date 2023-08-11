import { lazy } from "react";
import type { Path } from "react-router-dom";
import { generatePath } from "react-router-dom";
import type { AppRouteObject } from "../../routes";

export type ClientScopesParams = { realm: string };

const ClientScopesSection = lazy(() => import("../ClientScopesSection"));

export const ClientScopesRoute: AppRouteObject = {
  path: "/:realm/client-scopes",
  element: <ClientScopesSection />,
  breadcrumb: (t) => t("client-scopes:clientScopeList"),
  handle: {
    access: "view-clients",
  },
};

export const toClientScopes = (params: ClientScopesParams): Partial<Path> => ({
  pathname: generatePath(ClientScopesRoute.path, params),
});

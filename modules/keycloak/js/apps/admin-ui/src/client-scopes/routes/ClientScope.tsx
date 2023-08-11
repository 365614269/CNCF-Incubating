import { lazy } from "react";
import type { Path } from "react-router-dom";
import { generatePath } from "react-router-dom";
import type { AppRouteObject } from "../../routes";

export type ClientScopeTab = "settings" | "mappers" | "scope";

export type ClientScopeParams = {
  realm: string;
  id: string;
  tab: ClientScopeTab;
};

const EditClientScope = lazy(() => import("../EditClientScope"));

export const ClientScopeRoute: AppRouteObject = {
  path: "/:realm/client-scopes/:id/:tab",
  element: <EditClientScope />,
  breadcrumb: (t) => t("client-scopes:clientScopeDetails"),
  handle: {
    access: "view-clients",
  },
};

export const toClientScope = (params: ClientScopeParams): Partial<Path> => {
  const path = ClientScopeRoute.path;

  return {
    pathname: generatePath(path, params),
  };
};

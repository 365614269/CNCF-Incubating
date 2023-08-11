import { lazy } from "react";
import type { Path } from "react-router-dom";
import { generatePath } from "react-router-dom";
import type { AppRouteObject } from "../../routes";

export type ClientTab =
  | "settings"
  | "keys"
  | "credentials"
  | "roles"
  | "clientScopes"
  | "advanced"
  | "mappers"
  | "authorization"
  | "serviceAccount"
  | "permissions"
  | "sessions";

export type ClientParams = {
  realm: string;
  clientId: string;
  tab: ClientTab;
};

const ClientDetails = lazy(() => import("../ClientDetails"));

export const ClientRoute: AppRouteObject = {
  path: "/:realm/clients/:clientId/:tab",
  element: <ClientDetails />,
  breadcrumb: (t) => t("clients:clientSettings"),
  handle: {
    access: "query-clients",
  },
};

export const toClient = (params: ClientParams): Partial<Path> => ({
  pathname: generatePath(ClientRoute.path, params),
});

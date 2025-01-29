import { lazy } from "react";
import type { Path } from "react-router-dom";
import { generateEncodedPath } from "../../utils/generateEncodedPath";
import type { AppRouteObject } from "../../routes";

export type PermissionsConfigurationTabs =
  | "permissions"
  | "policies"
  | "evaluate";

export type PermissionsConfigurationTabsParams = {
  realm: string;
  tab: PermissionsConfigurationTabs;
};

const PermissionsConfigurationSection = lazy(
  () => import("../PermissionsConfigurationSection"),
);

export const PermissionsConfigurationTabsRoute: AppRouteObject = {
  path: "/:realm/permissions/:tab",
  element: <PermissionsConfigurationSection />,
  handle: {
    access: (accessChecker) =>
      accessChecker.hasAny("view-realm", "view-clients", "view-users"),
  },
};

export const toPermissionsConfigurationTabs = (
  params: PermissionsConfigurationTabsParams,
): Partial<Path> => ({
  pathname: generateEncodedPath(PermissionsConfigurationTabsRoute.path, params),
});

import { lazy } from "react";
import type { Path } from "react-router-dom";
import { generatePath } from "react-router-dom";
import type { AppRouteObject } from "../../routes";

export type DashboardTab = "info" | "providers";

export type DashboardParams = { realm?: string; tab?: DashboardTab };

const Dashboard = lazy(() => import("../Dashboard"));

export const DashboardRoute: AppRouteObject = {
  path: "/",
  element: <Dashboard />,
  breadcrumb: (t) => t("common:home"),
  handle: {
    access: "anyone",
  },
};

export const DashboardRouteWithRealm: AppRouteObject = {
  ...DashboardRoute,
  path: "/:realm",
};

export const DashboardRouteWithTab: AppRouteObject = {
  ...DashboardRoute,
  path: "/:realm/:tab",
};

export const toDashboard = (params: DashboardParams): Partial<Path> => {
  const pathname = params.realm
    ? params.tab
      ? DashboardRouteWithTab.path
      : DashboardRouteWithRealm.path
    : DashboardRoute.path;

  return {
    pathname: generatePath(pathname, params),
  };
};

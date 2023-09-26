import type UserSessionRepresentation from "@keycloak/keycloak-admin-client/lib/defs/userSessionRepresentation";
import {
  Button,
  List,
  ListItem,
  ListVariant,
  ToolbarItem,
} from "@patternfly/react-core";
import { CubesIcon } from "@patternfly/react-icons";
import { ReactNode, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";

import { adminClient } from "../admin-client";
import { toClient } from "../clients/routes/Client";
import { useAlerts } from "../components/alert/Alerts";
import { useConfirmDialog } from "../components/confirm-dialog/ConfirmDialog";
import { ListEmptyState } from "../components/list-empty-state/ListEmptyState";
import {
  Action,
  Field,
  KeycloakDataTable,
  LoaderFunction,
} from "../components/table-toolbar/KeycloakDataTable";
import { useRealm } from "../context/realm-context/RealmContext";
import { useWhoAmI } from "../context/whoami/WhoAmI";
import { keycloak } from "../keycloak";
import { toUser } from "../user/routes/User";
import useFormatDate from "../utils/useFormatDate";

export type ColumnName =
  | "username"
  | "start"
  | "lastAccess"
  | "clients"
  | "type";

export type SessionsTableProps = {
  loader: LoaderFunction<UserSessionRepresentation>;
  hiddenColumns?: ColumnName[];
  emptyInstructions?: string;
  logoutUser?: string;
  filter?: ReactNode;
  isSearching?: boolean;
  isPaginated?: boolean;
};

const UsernameCell = (row: UserSessionRepresentation) => {
  const { realm } = useRealm();
  return (
    <Link to={toUser({ realm, id: row.userId!, tab: "sessions" })}>
      {row.username}
    </Link>
  );
};

const ClientsCell = (row: UserSessionRepresentation) => {
  const { realm } = useRealm();
  return (
    <List variant={ListVariant.inline}>
      {Object.entries(row.clients!).map(([clientId, client]) => (
        <ListItem key={clientId}>
          <Link to={toClient({ realm, clientId, tab: "sessions" })}>
            {client}
          </Link>
        </ListItem>
      ))}
    </List>
  );
};

export default function SessionsTable({
  loader,
  hiddenColumns = [],
  emptyInstructions,
  logoutUser,
  filter,
  isSearching,
  isPaginated,
}: SessionsTableProps) {
  const { realm } = useRealm();
  const { whoAmI } = useWhoAmI();
  const { t } = useTranslation();
  const { addError } = useAlerts();
  const formatDate = useFormatDate();
  const [key, setKey] = useState(0);
  const refresh = () => setKey((value) => value + 1);

  const columns = useMemo(() => {
    const defaultColumns: Field<UserSessionRepresentation>[] = [
      {
        name: "username",
        displayKey: "user",
        cellRenderer: UsernameCell,
      },
      {
        name: "type",
        displayKey: "type",
      },
      {
        name: "start",
        displayKey: "started",
        cellRenderer: (row) => formatDate(new Date(row.start!)),
      },
      {
        name: "lastAccess",
        displayKey: "lastAccess",
        cellRenderer: (row) => formatDate(new Date(row.lastAccess!)),
      },
      {
        name: "ipAddress",
        displayKey: "ipAddress",
      },
      {
        name: "clients",
        displayKey: "clients",
        cellRenderer: ClientsCell,
      },
    ];

    return defaultColumns.filter(
      ({ name }) => !hiddenColumns.includes(name as ColumnName),
    );
  }, [realm, hiddenColumns]);

  const [toggleLogoutDialog, LogoutConfirm] = useConfirmDialog({
    titleKey: "logoutAllSessions",
    messageKey: "logoutAllDescription",
    continueButtonLabel: "confirm",
    onConfirm: async () => {
      try {
        await adminClient.users.logout({ id: logoutUser! });
        refresh();
      } catch (error) {
        addError("logoutAllSessionsError", error);
      }
    },
  });

  async function onClickSignOut(session: UserSessionRepresentation) {
    await adminClient.realms.deleteSession({ realm, session: session.id! });

    if (session.userId === whoAmI.getUserId()) {
      await keycloak.logout({ redirectUri: "" });
    } else {
      refresh();
    }
  }

  return (
    <>
      <LogoutConfirm />
      <KeycloakDataTable
        key={key}
        loader={loader}
        ariaLabelKey="titleSessions"
        searchPlaceholderKey="searchForSession"
        isPaginated={isPaginated}
        isSearching={isSearching}
        searchTypeComponent={filter}
        toolbarItem={
          logoutUser && (
            <ToolbarItem>
              <Button onClick={toggleLogoutDialog}>
                {t("logoutAllSessions")}
              </Button>
            </ToolbarItem>
          )
        }
        columns={columns}
        actions={[
          {
            title: t("signOut"),
            onRowClick: onClickSignOut,
          } as Action<UserSessionRepresentation>,
        ]}
        emptyState={
          <ListEmptyState
            hasIcon
            icon={CubesIcon}
            message={t("noSessions")}
            instructions={
              emptyInstructions ? emptyInstructions : t("noSessionsDescription")
            }
          />
        }
      />
    </>
  );
}

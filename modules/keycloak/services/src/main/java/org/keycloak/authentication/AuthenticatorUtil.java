/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.authentication;

import org.jboss.logging.Logger;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.authentication.actiontoken.DefaultActionToken;
import org.keycloak.common.ClientConnection;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static org.keycloak.services.managers.AuthenticationManager.FORCED_REAUTHENTICATION;
import static org.keycloak.services.managers.AuthenticationManager.SSO_AUTH;

public class AuthenticatorUtil {

    private static final Logger logger = Logger.getLogger(AuthenticatorUtil.class);

    // It is used for identification of note included in authentication session for storing callback provider factories
    public static String CALLBACKS_FACTORY_IDS_NOTE = "callbacksFactoryProviderIds";


    public static boolean isSSOAuthentication(AuthenticationSessionModel authSession) {
        return "true".equals(authSession.getAuthNote(SSO_AUTH));
    }

    public static boolean isForcedReauthentication(AuthenticationSessionModel authSession) {
        return "true".equals(authSession.getAuthNote(FORCED_REAUTHENTICATION));
    }

    /**
     * Set authentication session note for callbacks defined for {@link AuthenticationFlowCallbackFactory) factories
     *
     * @param authSession   authentication session
     * @param authFactoryId authentication factory ID which should be added to the authentication session note
     */
    public static void setAuthCallbacksFactoryIds(AuthenticationSessionModel authSession, String authFactoryId) {
        if (authSession == null || StringUtil.isBlank(authFactoryId)) return;

        final String callbacksFactories = authSession.getAuthNote(CALLBACKS_FACTORY_IDS_NOTE);

        if (StringUtil.isNotBlank(callbacksFactories)) {
            boolean containsProviderId = callbacksFactories.equals(authFactoryId) ||
                    callbacksFactories.contains(Constants.CFG_DELIMITER + authFactoryId) ||
                    callbacksFactories.contains(authFactoryId + Constants.CFG_DELIMITER);

            if (!containsProviderId) {
                authSession.setAuthNote(CALLBACKS_FACTORY_IDS_NOTE, callbacksFactories + Constants.CFG_DELIMITER + authFactoryId);
            }
        } else {
            authSession.setAuthNote(CALLBACKS_FACTORY_IDS_NOTE, authFactoryId);
        }
    }

    /**
     * Get set of Authentication factories IDs defined in authentication session as CALLBACKS_FACTORY_IDS_NOTE
     *
     * @param authSession authentication session
     * @return set of factories IDs
     */
    public static Set<String> getAuthCallbacksFactoryIds(AuthenticationSessionModel authSession) {
        if (authSession == null) return Collections.emptySet();

        final String callbacksFactories = authSession.getAuthNote(CALLBACKS_FACTORY_IDS_NOTE);

        if (StringUtil.isNotBlank(callbacksFactories)) {
            String[] split = callbacksFactories.split(Constants.CFG_DELIMITER);
            Set<String> set = new HashSet<>(split.length);
            for (String s : split) {
                set.add(s);
            }
            return Collections.unmodifiableSet(set);
        } else {
            return Collections.emptySet();
        }
    }


    /**
     * @param realm
     * @param flowId
     * @param providerId
     * @return all executions of given "provider_id" type. This is deep (recursive) obtain of executions of the particular flow
     */
    public static List<AuthenticationExecutionModel> getExecutionsByType(RealmModel realm, String flowId, String providerId) {
        List<AuthenticationExecutionModel> executions = new LinkedList<>();
        realm.getAuthenticationExecutionsStream(flowId).forEach(authExecution -> {
            if (providerId.equals(authExecution.getAuthenticator())) {
                executions.add(authExecution);
            } else if (authExecution.isAuthenticatorFlow() && authExecution.getFlowId() != null) {
                executions.addAll(getExecutionsByType(realm, authExecution.getFlowId(), providerId));
            }
        });
        return executions;
    }

    /**
     * Logouts all sessions that are different to the current authentication session
     * managed in the action context.
     *
     * @param context The required action context
     */
    public static void logoutOtherSessions(RequiredActionContext context) {
        logoutOtherSessions(context.getSession(), context.getRealm(), context.getUser(),
                context.getAuthenticationSession(), context.getConnection(), context.getHttpRequest());
    }

    /**
     * Logouts all sessions that are different to the current authentication session
     * managed in the action token context.
     *
     * @param context The required action token context
     */
    public static void logoutOtherSessions(ActionTokenContext<? extends DefaultActionToken> context) {
        logoutOtherSessions(context.getSession(), context.getRealm(), context.getAuthenticationSession().getAuthenticatedUser(),
                context.getAuthenticationSession(), context.getClientConnection(), context.getRequest());
    }

    private static void logoutOtherSessions(KeycloakSession session, RealmModel realm, UserModel user,
            AuthenticationSessionModel authSession, ClientConnection conn, HttpRequest req) {
        session.sessions().getUserSessionsStream(realm, user)
                .filter(s -> !Objects.equals(s.getId(), authSession.getParentSession().getId()))
                .collect(Collectors.toList()) // collect to avoid concurrent modification as backchannelLogout removes the user sessions.
                .forEach(s -> AuthenticationManager.backchannelLogout(session, realm, s, session.getContext().getUri(),
                        conn, req.getHttpHeaders(), true)
                );
    }
}

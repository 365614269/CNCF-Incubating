package org.keycloak.services.util;

import org.keycloak.common.ClientConnection;
import org.keycloak.common.constants.ServiceAccountConstants;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.UserSessionCrossDCManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.utils.OAuth2Error;

public class UserSessionUtil {

    public static UserSessionModel findValidSession(KeycloakSession session, RealmModel realm, AccessToken token, EventBuilder event, ClientModel client) {
        OAuth2Error error = new OAuth2Error().json(false).realm(realm);
        if (token.getSessionState() == null) {
            return createTransientSessionForClient(session, realm, token, client);
        }

        UserSessionModel userSession = new UserSessionCrossDCManager(session).getUserSessionWithClient(realm, token.getSessionState(), false, client.getId());
        UserSessionModel offlineUserSession = null;
        if (AuthenticationManager.isSessionValid(realm, userSession)) {
            checkTokenIssuedAt(realm, token, userSession, event, client);
            event.session(userSession);
            return userSession;
        } else {
            offlineUserSession = new UserSessionCrossDCManager(session).getUserSessionWithClient(realm, token.getSessionState(), true, client.getId());
            if (AuthenticationManager.isOfflineSessionValid(realm, offlineUserSession)) {
                checkTokenIssuedAt(realm, token, offlineUserSession, event, client);
                event.session(offlineUserSession);
                return offlineUserSession;
            }
        }

        if (userSession == null && offlineUserSession == null) {
            event.error(Errors.USER_SESSION_NOT_FOUND);
            throw error.invalidToken("User session not found or doesn't have client attached on it");
        }

        if (userSession != null) {
            event.session(userSession);
        } else {
            event.session(offlineUserSession);
        }

        event.error(Errors.SESSION_EXPIRED);
        throw error.invalidToken("Session expired");
    }

    private static UserSessionModel createTransientSessionForClient(KeycloakSession session, RealmModel realm, AccessToken token, ClientModel client) {
        OAuth2Error error = new OAuth2Error().json(false).realm(realm);
        // create a transient session
        UserModel user = TokenManager.lookupUserFromStatelessToken(session, realm, token);
        if (user == null) {
            throw error.invalidToken("User not found");
        }
        ClientConnection clientConnection = session.getContext().getConnection();
        UserSessionModel userSession = new UserSessionManager(session).createUserSession(KeycloakModelUtils.generateId(), realm, user, user.getUsername(), clientConnection.getRemoteAddr(),
                ServiceAccountConstants.CLIENT_AUTH, false, null, null, UserSessionModel.SessionPersistenceState.TRANSIENT);
        // attach an auth session for the client
        RootAuthenticationSessionModel rootAuthSession = session.authenticationSessions().createRootAuthenticationSession(realm);
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);
        authSession.setAuthenticatedUser(userSession.getUser());
        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authSession.setClientNote(OIDCLoginProtocol.ISSUER, Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        AuthenticationManager.setClientScopesInSession(authSession);
        TokenManager.attachAuthenticationSession(session, userSession, authSession);
        return userSession;
    }

    private static void checkTokenIssuedAt(RealmModel realm, AccessToken token, UserSessionModel userSession, EventBuilder event, ClientModel client) {
        OAuth2Error error = new OAuth2Error().json(false).realm(realm);
        if (token.isIssuedBeforeSessionStart(userSession.getStarted())) {
            event.error(Errors.INVALID_TOKEN);
            throw error.invalidToken("Stale token");
        }

        AuthenticatedClientSessionModel clientSession = userSession.getAuthenticatedClientSessionByClient(client.getId());
        if (token.isIssuedBeforeSessionStart(clientSession.getStarted())) {
            event.error(Errors.INVALID_TOKEN);
            throw error.invalidToken("Stale token");
        }
    }
}

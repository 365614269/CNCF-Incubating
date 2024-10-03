/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.organization.utils;

import static java.util.Optional.ofNullable;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;

import org.keycloak.OAuth2Constants;
import org.keycloak.TokenVerifier;
import org.keycloak.authentication.actiontoken.inviteorg.InviteOrgActionToken;
import org.keycloak.common.Profile;
import org.keycloak.common.Profile.Feature;
import org.keycloak.common.VerificationException;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.Constants;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.GroupModel.Type;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.organization.OrganizationProvider;
import org.keycloak.organization.protocol.mappers.oidc.OrganizationScope;
import org.keycloak.services.ErrorResponse;
import org.keycloak.sessions.AuthenticationSessionModel;

public class Organizations {

    public static boolean canManageOrganizationGroup(KeycloakSession session, GroupModel group) {
        if (!Type.ORGANIZATION.equals(group.getType())) {
            return true;
        }

        if (Profile.isFeatureEnabled(Feature.ORGANIZATION)) {
            OrganizationModel organization = resolveOrganization(session);

            return organization != null && organization.getId().equals(group.getName());
        }

        return true;
    }

    public static List<IdentityProviderModel> resolveHomeBroker(KeycloakSession session, UserModel user) {
        OrganizationProvider provider = getProvider(session);
        RealmModel realm = session.getContext().getRealm();
        List<OrganizationModel> organizations = Optional.ofNullable(user).stream().flatMap(provider::getByMember)
                .filter(OrganizationModel::isEnabled)
                .filter((org) -> org.isManaged(user))
                .toList();

        if (organizations.isEmpty()) {
            return List.of();
        }

        List<IdentityProviderModel> brokers = new ArrayList<>();

        for (OrganizationModel organization : organizations) {
            // user is a managed member, try to resolve the origin broker and redirect automatically
            List<IdentityProviderModel> organizationBrokers = organization.getIdentityProviders().toList();
            session.users().getFederatedIdentitiesStream(realm, user)
                    .map(f -> {
                        IdentityProviderModel broker = session.identityProviders().getByAlias(f.getIdentityProvider());

                        if (!organizationBrokers.contains(broker)) {
                            return null;
                        }

                        FederatedIdentityModel identity = session.users().getFederatedIdentity(realm, user, broker.getAlias());

                        if (identity != null) {
                            return broker;
                        }

                        return null;
                    }).filter(Objects::nonNull)
                    .forEach(brokers::add);
        }

        return brokers;
    }

    public static Consumer<GroupModel> removeGroup(KeycloakSession session, RealmModel realm) {
        return group -> {
            if (!Type.ORGANIZATION.equals(group.getType())) {
                realm.removeGroup(group);
                return;
            }

            OrganizationModel current = resolveOrganization(session);

            try {
                OrganizationProvider provider = getProvider(session);

                session.getContext().setOrganization(provider.getById(group.getName()));

                realm.removeGroup(group);
            } finally {
                session.getContext().setOrganization(current);
            }
        };
    }

    public static boolean isEnabledAndOrganizationsPresent(OrganizationProvider orgProvider) {
        return orgProvider != null && orgProvider.isEnabled() && orgProvider.count() != 0;
    }

    public static boolean isEnabledAndOrganizationsPresent(KeycloakSession session) {
        if (!Profile.isFeatureEnabled(Feature.ORGANIZATION)) {
            return false;
        }

        OrganizationProvider provider = getProvider(session);

        return isEnabledAndOrganizationsPresent(provider);
    }

    public static void checkEnabled(OrganizationProvider provider) {
        if (provider == null || !provider.isEnabled()) {
            throw ErrorResponse.error("Organizations not enabled for this realm.", Response.Status.NOT_FOUND);
        }
    }

    public static InviteOrgActionToken parseInvitationToken(HttpRequest request) throws VerificationException {
        MultivaluedMap<String, String> queryParameters = request.getUri().getQueryParameters();
        String tokenFromQuery = queryParameters.getFirst(Constants.TOKEN);

        if (tokenFromQuery == null) {
            return null;
        }

        return TokenVerifier.create(tokenFromQuery, InviteOrgActionToken.class).getToken();
    }

    public static String getEmailDomain(String email) {
        if (email == null) {
            return null;
        }

        int domainSeparator = email.indexOf('@');

        if (domainSeparator == -1) {
            return null;
        }

        return email.substring(domainSeparator + 1);
    }

    public static OrganizationModel resolveOrganization(KeycloakSession session) {
        return resolveOrganization(session, null, null);
    }

    public static OrganizationModel resolveOrganization(KeycloakSession session, UserModel user) {
        return resolveOrganization(session, user, null);
    }

    public static OrganizationModel resolveOrganization(KeycloakSession session, UserModel user, String domain) {
        if (!session.getContext().getRealm().isOrganizationsEnabled()) {
            return null;
        }

        Optional<OrganizationModel> organization = Optional.ofNullable(session.getContext().getOrganization());

        if (organization.isPresent()) {
            // resolved from current keycloak session
            return organization.get();
        }

        OrganizationProvider provider = getProvider(session);

        if (provider.count() == 0) {
            return null;
        }

        AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();

        if (authSession != null) {
            String rawScopes = authSession.getClientNote(OAuth2Constants.SCOPE);
            OrganizationScope scope = OrganizationScope.valueOfScope(rawScopes);

            List<OrganizationModel> organizations = ofNullable(authSession.getAuthNote(OrganizationModel.ORGANIZATION_ATTRIBUTE))
                    .map(provider::getById)
                    .map(List::of)
                    .orElseGet(() -> scope == null ? List.of() : scope.resolveOrganizations(user, rawScopes, session).toList());

            if (organizations.size() == 1) {
                // single organization mapped from authentication session
                return organizations.get(0);
            } else if (scope != null) {
                // organization scope requested but no single organization mapped from the scope
                return null;
            }
        }

        organization = ofNullable(user).stream().flatMap(provider::getByMember)
                .filter(o -> o.isEnabled() && provider.isManagedMember(o, user))
                .findAny();

        if (organization.isPresent()) {
            return organization.get();
        }

        if (user != null && domain == null) {
            domain = getEmailDomain(user.getEmail());
        }

        return ofNullable(domain)
                .map(provider::getByDomainName)
                .orElse(null);
    }

    public static OrganizationProvider getProvider(KeycloakSession session) {
        return session.getProvider(OrganizationProvider.class);
    }

    public static boolean isRegistrationAllowed(KeycloakSession session, RealmModel realm) {
        if (session.getContext().getOrganization() != null) return true;
        return realm.isRegistrationAllowed();
    }
}

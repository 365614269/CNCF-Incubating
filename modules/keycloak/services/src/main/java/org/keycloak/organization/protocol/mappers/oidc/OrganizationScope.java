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

package org.keycloak.organization.protocol.mappers.oidc;

import static org.keycloak.organization.utils.Organizations.getProvider;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.keycloak.common.util.TriFunction;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeDecorator;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.UserModel;
import org.keycloak.organization.utils.Organizations;
import org.keycloak.protocol.oidc.OIDCLoginProtocolFactory;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.utils.StringUtil;

/**
 * <p>An enum with utility methods to process the {@link OIDCLoginProtocolFactory#ORGANIZATION} scope.
 *
 * <p>The {@link OrganizationScope} behaves like a dynamic scopes so that access to organizations is granted depending
 * on how the client requests the {@link OIDCLoginProtocolFactory#ORGANIZATION} scope.
 */
public enum OrganizationScope {

    /**
     * Maps to any organization a user is a member. When this scope is requested by clients, all the organizations
     * the user is a member are granted.
     */
    ALL("*"::equals,
            (user, scopes, session) -> {
                if (user == null) {
                    return Stream.empty();
                }
                return getProvider(session).getByMember(user);
            },
            (organizations) -> true,
            (current, previous) -> valueOfScope(current) == null ? previous : current),

    /**
     * Maps to a specific organization the user is a member. When this scope is requested by clients, only the
     * organization specified in the scope is granted.
     */
    SINGLE(StringUtil::isNotBlank,
            (user, scopes, session) -> {
                OrganizationModel organization = parseScopeParameter(scopes)
                        .map(OrganizationScope::parseScopeValue)
                        .map(alias -> getProvider(session).getByAlias(alias))
                        .filter(Objects::nonNull)
                        .findAny()
                        .orElse(null);

                if (organization == null) {
                    return Stream.empty();
                }

                if (user == null || organization.isMember(user)) {
                    return Stream.of(organization);
                }

                return Stream.empty();
            },
            (organizations) -> organizations.findAny().isPresent(),
            (current, previous) -> {
                if (current.equals(previous)) {
                    return current;
                }

                if (OrganizationScope.ALL.equals(valueOfScope(current))) {
                    return previous;
                }

                return null;
            }),

    /**
     * Maps to a single organization if the user is a member of a single organization. When this scope is requested by clients,
     * the user will be asked to select and organization if a member of multiple organizations or, in case the user is a
     * member of a single organization, grant access to that organization.
     */
    ANY(""::equals,
            (user, scopes, session) -> {
                if (user == null) {
                    return Stream.empty();
                }

                List<OrganizationModel> organizations = getProvider(session).getByMember(user).toList();

                if (organizations.size() == 1) {
                    return organizations.stream();
                }

                ClientSessionContext context = (ClientSessionContext) session.getAttribute(ClientSessionContext.class.getName());

                if (context == null) {
                    return Stream.empty();
                }

                AuthenticatedClientSessionModel clientSession = context.getClientSession();
                String orgId = clientSession.getNote(OrganizationModel.ORGANIZATION_ATTRIBUTE);

                if (orgId == null) {
                    return Stream.empty();
                }

                return organizations.stream().filter(o -> o.getId().equals(orgId));
            },
            (organizations) -> true,
            (current, previous) -> {
                if (current.equals(previous)) {
                    return current;
                }

                if (OrganizationScope.ALL.equals(valueOfScope(current))) {
                    return previous;
                }

                return null;
            });

    private static final Pattern SCOPE_PATTERN = Pattern.compile(OIDCLoginProtocolFactory.ORGANIZATION + ":*".replace("*", "(.*)"));

    /**
     * <p>Resolves the value of the scope from its raw format. For instance, {@code organization:<value>} will resolve to {@code <value>}.
     *
     * <p>If no value is provided, like in {@code organization}, an empty string is returned instead.
     */
    private final Predicate<String> valueMatcher;

    /**
     * Resolves the organizations based on the values of the scope.
     */
    private final TriFunction<UserModel, String, KeycloakSession, Stream<OrganizationModel>> valueResolver;

    /**
     * Validate the value of the scope based on how they map to existing organizations.
     */
    private final Predicate<Stream<OrganizationModel>> valueValidator;

    /**
     * Resolves the name of the scope when requesting a scope using a different format.
     */
    private final BiFunction<String, String, String> nameResolver;

    OrganizationScope(Predicate<String> valueMatcher, TriFunction<UserModel, String, KeycloakSession, Stream<OrganizationModel>> valueResolver, Predicate<Stream<OrganizationModel>> valueValidator, BiFunction<String, String, String> nameResolver) {
        this.valueMatcher = valueMatcher;
        this.valueResolver = valueResolver;
        this.valueValidator = valueValidator;
        this.nameResolver = nameResolver;
    }

    /**
     * Returns the organizations mapped from the {@code scope} based on the given {@code user}.
     *
     * @param user the user. Can be {@code null} depending on how the scope resolves its value.
     * @param scope the string referencing the scope
     * @param session the session
     * @return the organizations mapped to the given {@code user}. Or an empty stream if no organizations were mapped from the {@code scope} parameter.
     */
    public Stream<OrganizationModel> resolveOrganizations(UserModel user, String scope, KeycloakSession session) {
        if (scope == null) {
            return Stream.empty();
        }
        return valueResolver.apply(user, scope, session).filter(OrganizationModel::isEnabled);
    }

    /**
     * Returns a {@link ClientScopeModel} with the given {@code name} for this scope.
     *
     * @param name the name of the scope
     * @param user the user
     * @param session the session
     * @return the {@link ClientScopeModel}
     */
    public ClientScopeModel toClientScope(String name, UserModel user, KeycloakSession session) {
        OrganizationScope scope = valueOfScope(name);

        if (scope == null) {
            return null;
        }

        KeycloakContext context = session.getContext();
        ClientModel client = context.getClient();
        ClientScopeModel orgScope = getOrganizationClientScope(client, session);

        if (orgScope == null) {
            return null;
        }

        Stream<OrganizationModel> organizations = scope.resolveOrganizations(user, name, session);

        if (valueValidator.test(organizations)) {
            return new ClientScopeDecorator(orgScope, name);
        }

        return null;
    }

    /**
     * <p>Resolves the name of this scope based on the given set of {@code scopes} and the {@code previous} name.
     *
     * <p>The scope name can be mapped to another scope depending on its semantics. Otherwise, it will map to
     * the same name. This method is mainly useful to recognize if a scope previously granted is still valid
     * and can be mapped to the new scope being requested. For instance, when refreshing tokens.
     *
     * @param scopes the scopes to resolve the name from
     * @param previous the previous name of this scope
     * @return the name of the scope
     */
    public String resolveName(Set<String> scopes, String previous) {
        for (String scope : scopes) {
            String resolved = nameResolver.apply(scope, previous);

            if (resolved == null) {
                continue;
            }

            return resolved;
        }

        return null;
    }

    /**
     * Returns a {@link OrganizationScope} instance based on the given {@code rawScope}.
     *
     * @param rawScope the string referencing the scope
     * @return the organization scope that maps the given {@code rawScope}
     */
    public static OrganizationScope valueOfScope(String rawScope) {
        if (rawScope == null) {
            return null;
        }
        return parseScopeParameter(rawScope)
                .map(s -> {
                    for (OrganizationScope scope : values()) {
                        if (scope.valueMatcher.test(parseScopeValue(s))) {
                            return scope;
                        }
                    }
                    return null;
                }).filter(Objects::nonNull)
                .findAny()
                .orElse(null);
    }

    private static String parseScopeValue(String scope) {
        if (!hasOrganizationScope(scope)) {
            return null;
        }

        if (scope.equals(OIDCLoginProtocolFactory.ORGANIZATION)) {
            return "";
        }

        Matcher matcher = SCOPE_PATTERN.matcher(scope);

        if (matcher.matches()) {
            return matcher.group(1);
        }

        return null;
    }

    private ClientScopeModel getOrganizationClientScope(ClientModel client, KeycloakSession session) {
        if (!Organizations.isEnabledAndOrganizationsPresent(session)) {
            return null;
        }

        Map<String, ClientScopeModel> scopes = new HashMap<>(client.getClientScopes(true));
        scopes.putAll(client.getClientScopes(false));

        return scopes.get(OIDCLoginProtocolFactory.ORGANIZATION);
    }

    private static boolean hasOrganizationScope(String scope) {
        return scope != null && scope.contains(OIDCLoginProtocolFactory.ORGANIZATION);
    }

    private static Stream<String> parseScopeParameter(String rawScope) {
        return TokenManager.parseScopeParameter(rawScope)
                .filter(OrganizationScope::hasOrganizationScope);
    }
}

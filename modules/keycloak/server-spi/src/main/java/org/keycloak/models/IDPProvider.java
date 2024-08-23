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
package org.keycloak.models;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.keycloak.provider.Provider;

/**
 * The {@code IDPProvider} is concerned with the storage/retrieval of the configured identity providers in Keycloak. In
 * other words, it is a provider of identity providers (IDPs) and, as such, handles the CRUD operations for IDPs.
 * </p>
 * It is not to be confused with the {@code IdentityProvider} found in server-spi-private as that provider is meant to be
 * implemented by actual identity providers that handle the logic of authenticating users with third party brokers, such
 * as Microsoft, Google, Github, LinkedIn, etc.
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public interface IDPProvider extends Provider {

    /**
     * Creates a new identity provider from the specified model.
     *
     * @param model a {@link IdentityProviderModel} containing the identity provider's data.
     * @return the model of the created identity provider.
     */
    IdentityProviderModel create(IdentityProviderModel model);

    /**
     * Updates the identity provider using the specified model.
     *
     * @param model a {@link IdentityProviderModel} containing the identity provider's data.
     */
    void update(IdentityProviderModel model);

    /**
     * Removes the identity provider with the specified alias.
     *
     * @param providerAlias the alias of the identity provider to be removed.
     * @return {@code true} if an IDP with the specified alias was found and removed; {@code false} otherwise.
     */
    boolean remove(String providerAlias);

    /**
     * Removes all identity providers from the realm.
     */
    void removeAll();

    /**
     * Obtains the identity provider with the specified internal id.
     *
     * @param internalId the identity provider's internal id.
     * @return a reference to the identity provider, or {@code null} if no provider is found.
     */
    IdentityProviderModel getById(String internalId);

    /**
     * Obtains the identity provider with the specified alias.
     *
     * @param alias the identity provider's alias.
     * @return a reference to the identity provider, or {@code null} if no provider is found.
     */
    IdentityProviderModel getByAlias(String alias);

    /**
     * Obtains the identity provider whose id or alias match the specified key.
     *
     * @param key a {@code String} representing either the identity provider's id or alias.
     * @return a reference to the identity provider, or {@code null} if no provider is found.
     */
    default IdentityProviderModel getByIdOrAlias(String key) {
        IdentityProviderModel identityProvider = getById(key);
        return identityProvider != null ? identityProvider : getByAlias(key);
    }

    /**
     * Returns all identity providers in the current realm.
     *
     * @return a non-null stream of {@link IdentityProviderModel}s.
     */
    default Stream<IdentityProviderModel> getAllStream() {
        return getAllStream(Map.of(), null, null);
    }

    /**
     * Returns all identity providers in the realm filtered according to the specified parameters.
     *
     * @param attrs a {@code Map} containig identity provider config attributes that must be matched.
     * @param first the position of the first result to be processed (pagination offset). Ignored if negative or {@code null}.
     * @param max the maximum number of results to be returned. Ignored if negative or {@code null}.
     * @return a non-null stream of {@link IdentityProviderModel}s that match the search criteria.
     */
    Stream<IdentityProviderModel> getAllStream(Map<String, String> attrs, Integer first, Integer max);

    /**
     * Returns all identity providers associated with the organization with the provided id.
     *
     * @param orgId the id of the organization.
     * @param first the position of the first result to be processed (pagination offset). Ignored if negative or {@code null}.
     * @param max the maximum number of results to be returned. Ignored if negative or {@code null}.
     * @return a non-null stream of {@link IdentityProviderModel}s that match the search criteria.
     */
    default Stream<IdentityProviderModel> getByOrganization(String orgId, Integer first, Integer max) {
        return getAllStream(Map.of(IdentityProviderModel.ORGANIZATION_ID, orgId != null ? orgId : ""), first, max);
    }

    /**
     * Returns the aliases of all identity providers whose {@code firstBrokerLoginFlowId} or {@code postBrokerLoginFlowId}
     * matches the provided {@code flowId}.
     *
     * @param flowId the id of the flow.
     * @param search an optional {@link String} representing an identity provider alias (partial or exact). If the value is enclosed
     *               in double quotes, the method treats it as an exact search (e.g. {@code "name"}). If the value is enclosed in
     *               wildcards, the method treats it as an infix search (e.g. {@code *name*}). Otherwise, the method treats it as a
     *               prefix search (i.e. {@code name*} and {@code name} return the same results).
     * @param first the position of the first result to be processed (pagination offset). Ignored if negative or {@code null}.
     * @param max the maximum number of results to be returned. Ignored if negative or {@code null}.
     * @return a non-null stream of {@link IdentityProviderModel}s that match the search criteria.
     */
    Stream<String> getByFlow(String flowId, String search, Integer first, Integer max);

    /**
     * Returns all identity providers available for login, according to the specified mode. An IDP can be used for login
     * if it is enabled, is not a link-only IDP, and is not configured to be hidden on login page.
     * </p>
     * The mode parameter may narrow the list of IDPs that are available. {@code FETCH_MODE.REALM_ONLY} fetches only realm-level
     * IDPs (i.e. those not associated with any org). {@code FETCH_MODE.ORG_ONLY} will work together with the {@code organizationId}
     * parameter. If the latter is set, only the IDPs associated with that org will be returned. Otherwise, the method returns
     * the IDPs associated with any org. {@code FETCH_MODE.ALL} combines both approaches, returning both the realm-level
     * IDPs with those associated with organizations (or a specific organization as per the {@code organizationId} param).
     *
     * @param mode the fetch mode to be used. Can be {@code REALM_ONLY}, {@code ORG_ONLY}, or {@code ALL}.
     * @param organizationId an optional organization ID. If present and the mode is not {@code REALM_ONLY}, the param indicates
     *                       that only IDPs associated with the specified organization are to be returned.
     * @return a non-null stream of {@link IdentityProviderModel}s that are suitable for being displayed in the login pages.
     */
    default Stream<IdentityProviderModel> getForLogin(FetchMode mode, String organizationId) {
        Stream<IdentityProviderModel> result = Stream.of();
        if (mode == FetchMode.REALM_ONLY || mode == FetchMode.ALL) {
            // fetch all realm-only IDPs - i.e. those not associated with orgs.
            Map<String, String> searchOptions = LoginFilter.getLoginSearchOptions();
            searchOptions.put(IdentityProviderModel.ORGANIZATION_ID, null);
            result = Stream.concat(result, getAllStream(searchOptions, null, null));
        }
        if (mode == FetchMode.ORG_ONLY || mode == FetchMode.ALL) {
            // fetch IDPs associated with organizations.
            Map<String, String> searchOptions = LoginFilter.getLoginSearchOptions();
            if (organizationId != null) {
                // we want the IDPs associated with a specific org.
                searchOptions.put(IdentityProviderModel.ORGANIZATION_ID, organizationId);
            }
            searchOptions.put(OrganizationModel.BROKER_PUBLIC, "true");
            result = Stream.concat(result, getAllStream(searchOptions, null, null));
        }
        return result;
    }

    /**
     * Returns the number of IDPs in the realm.
     *
     * @return the number of IDPs found in the realm.
     */
    long count();

    /**
     * Checks whether the realm has any configured identity providers or not.
     *
     * @return {@code true} if the realm has at least one configured identity provider (federation is enabled); {@code false}
     * otherwise.
     */
    default boolean isIdentityFederationEnabled() {
        return count() > 0;
    }

    /**
     * Enum to control how login identity providers should be fetched.
     */
    enum FetchMode {
        /** only realm-level providers should be fetched (not linked to any organization) **/
        REALM_ONLY,
        /** only providers linked to organizations should be fetched **/
        ORG_ONLY,
        /** all providers should fetched, regardless of being linked to an organization or not **/
        ALL
    }

    /**
     * Enum that contains all fields that are considered when deciding if a provider should be available for login or not.
     */
    enum LoginFilter {

        ENABLED(IdentityProviderModel.ENABLED, Boolean.TRUE.toString(), IdentityProviderModel::isEnabled),

        LINK_ONLY(IdentityProviderModel.LINK_ONLY, Boolean.FALSE.toString(), Predicate.not(IdentityProviderModel::isLinkOnly)),

        HIDE_ON_LOGIN(IdentityProviderModel.HIDE_ON_LOGIN, Boolean.FALSE.toString(), Predicate.not(IdentityProviderModel::isHideOnLogin));

        private final String key;
        private final String value;
        private final Predicate<IdentityProviderModel> filter;

        LoginFilter(String key, String value, java.util.function.Predicate<IdentityProviderModel> filter) {
            this.key = key;
            this.value = value;
            this.filter = filter;
        }

        public String getKey() {
            return key;
        }

        public String getValue() {
            return value;
        }

        public Predicate<IdentityProviderModel> getFilter() {
            return filter;
        }

        public static Map<String, String> getLoginSearchOptions() {
            return Stream.of(values()).collect(Collectors.toMap(LoginFilter::getKey, LoginFilter::getValue, (v1, v2) -> v1, LinkedHashMap::new));
        }

        public static Predicate<IdentityProviderModel> getLoginPredicate() {
            return ((Predicate<IdentityProviderModel>) Objects::nonNull)
                    .and(Stream.of(values()).map(LoginFilter::getFilter).reduce(Predicate::and).get());
        }
    }

    /**
     * Creates a new identity provider mapper from the specified model.
     *
     * @param model a {@link IdentityProviderMapperModel} containing the identity provider mapper's data.
     * @return the model of the created identity provider mapper.
     */
    IdentityProviderMapperModel createMapper(IdentityProviderMapperModel model);

    /**
     * Updates the identity provider mapper using the specified model.
     *
     * @param model a {@link IdentityProviderMapperModel} containing the identity provider mapper's data.
     */
    void updateMapper(IdentityProviderMapperModel model);

    /**
     * Removes the given identity provider mapper.
     *
     * @param model a {@link IdentityProviderMapperModel} to be deleted.
     * @return {@code true} if an identity provider mapper was removed; {@code false} otherwise.
     */
    boolean removeMapper(IdentityProviderMapperModel model);

    /**
     * Removes all identity provider mappers from the realm.
     */
    void removeAllMappers();

    /**
     * Obtains the identity provider mapper with the specified id.
     *
     * @param id the identity provider mapper's id.
     * @return a reference to the identity provider mapper, or {@code null} if no mapper is found.
     */
    IdentityProviderMapperModel getMapperById(String id);

    /**
     * Obtains the identity provider mapper with the provided identity provider alias and name.
     *
     * @param identityProviderAlias the identity provider alias.
     * @param name the identity provider mapper's name.
     * @return a reference to the identity provider mapper, or {@code null} if no provider is found.
     */
    IdentityProviderMapperModel getMapperByName(String identityProviderAlias, String name);

    /**
     * Returns all identity provider mappers as a stream.
     * @return Stream of {@link IdentityProviderMapperModel}. Never returns {@code null}.
     */
    Stream<IdentityProviderMapperModel> getMappersStream();

    /**
     * Returns identity provider mappers by the provided alias as a stream.
     * @param identityProviderAlias {@code String} Identity provider alias to filter results.
     * @return Stream of {@link IdentityProviderMapperModel} Never returns {@code null}.
     */
    Stream<IdentityProviderMapperModel> getMappersByAliasStream(String identityProviderAlias);
}

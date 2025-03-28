/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.authorization;

import static java.util.function.Predicate.not;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import org.keycloak.Config;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.Scope;
import org.keycloak.authorization.policy.provider.PartialEvaluationPolicyProvider;
import org.keycloak.authorization.policy.provider.PartialEvaluationStorageProvider;
import org.keycloak.authorization.policy.provider.PartialEvaluationStorageProvider.EvaluationContext;
import org.keycloak.authorization.policy.provider.PolicyProvider;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.authorization.Logic;
import org.keycloak.representations.idm.authorization.ResourceType;

public class PartialEvaluator {

    public List<Predicate> applyAuthorizationFilters(KeycloakSession session, ResourceType resourceType, PartialEvaluationStorageProvider storage, RealmModel realm, CriteriaBuilder builder, CriteriaQuery<?> queryBuilder, Path<?> path) {
        if (!AdminPermissionsSchema.SCHEMA.isAdminPermissionsEnabled(realm)) {
            // feature not enabled, if a storage evaluator is provided try to resolve any filter from there
            return storage == null ? List.of() : storage.getFilters(new EvaluationContext(resourceType, queryBuilder, path, Set.of(), Set.of()));
        }

        KeycloakContext context = session.getContext();
        UserModel adminUser = context.getUser();

        if (skipPartialEvaluation(session, adminUser, realm, resourceType)) {
            // only run partial evaluation if the admin user does not have view-* or manage-* role for specified resourceType or has any query-* role
            return List.of();
        }

        // collect the result from the partial evaluation so that the filters can be applied
        PartialResourceEvaluationResult result = evaluate(session, adminUser, resourceType);
        EvaluationContext evaluationContext = new EvaluationContext(resourceType, queryBuilder, path, new HashSet<>(), new HashSet<>());

        if (AdminPermissionsSchema.USERS.equals(resourceType)) {
            PartialResourceEvaluationResult evaluateGroups = evaluate(session, adminUser, AdminPermissionsSchema.GROUPS);

            evaluationContext.allowedGroupIds().addAll(evaluateGroups.allowedIds());
            evaluationContext.deniedGroupIds().addAll(evaluateGroups.deniedIds());
        }

        List<Predicate> predicates = new ArrayList<>();
        Set<String> deniedIds = result.deniedIds();

        if (!deniedIds.isEmpty()) {
            // add filters to remove denied resources from the result set
            predicates.add(builder.not(path.get("id").in(deniedIds)));
        }

        List<Predicate> storageFilters = storage == null ? List.of() : storage.getFilters(evaluationContext);
        List<Predicate> storageNegateFilters = storage == null ? List.of() : storage.getNegateFilters(evaluationContext);

        predicates.addAll(storageNegateFilters);

        if (storageFilters.isEmpty() && (result.isResourceTypedDenied() || (!deniedIds.isEmpty() && result.rawAllowedIds().isEmpty()))) {
            // do not return any result because there is no filter from the evaluator, and access is denied for the resource type
            return List.of(builder.equal(path.get("id"), "none"));
        }

        Set<String> allowedIds = result.allowedIds();

        if (allowedIds.isEmpty()) {
            // no resources granted, filter them based on any filter previously set
            predicates.addAll(storageFilters);
            return predicates;
        }

        if (storageFilters.isEmpty()) {
            // no filter from the evaluator, filter based on the resources that were granted
            predicates.add(builder.and(path.get("id").in(allowedIds)));
        } else {
            // there are filters from the evaluator, the resources granted will be a returned using a or condition
            List<Predicate> orPredicates = new ArrayList<>(storageFilters);
            orPredicates.add(path.get("id").in(allowedIds));
            predicates.add(builder.or(orPredicates.toArray(new Predicate[0])));
        }

        return predicates;
    }

    private record PartialResourceEvaluationResult(ResourceType resourceType, Set<String> rawAllowedIds, Set<String> rawDeniedIds) {
        Set<String> allowedIds() {
            return rawAllowedIds.stream().filter(not(resourceType.getType()::equals)).collect(Collectors.toSet());
        }

        Set<String> deniedIds() {
            return rawDeniedIds.stream().filter(not(resourceType.getType()::equals)).collect(Collectors.toSet());
        }

        boolean isResourceTypedDenied() {
            return rawAllowedIds.isEmpty() && (rawDeniedIds.isEmpty() || (rawDeniedIds.size() == 1 && rawDeniedIds.contains(resourceType.getType())));
        }
    }

    private PartialResourceEvaluationResult evaluate(KeycloakSession session, UserModel adminUser, ResourceType resourceType) {
        Set<String> allowedIds = new HashSet<>();
        Set<String> deniedIds = new HashSet<>();
        List<PartialEvaluationPolicyProvider> policyProviders = getPartialEvaluationPolicyProviders(session);

        for (PartialEvaluationPolicyProvider policyProvider : policyProviders) {
            policyProvider.getPermissions(session, resourceType, adminUser).forEach(permission -> {
                if (permission.getScopes().stream().map(Scope::getName).noneMatch(name -> name.startsWith(AdminPermissionsSchema.VIEW))) {
                    return;
                }
                Set<String> ids = permission.getResources().stream().map(Resource::getName).collect(Collectors.toSet());
                Set<Policy> policies = permission.getAssociatedPolicies();

                for (Policy policy : policies) {
                    PartialEvaluationPolicyProvider provider = policyProviders.stream().filter((p) -> p.supports(policy)).findAny().orElse(null);

                    if (provider == null) {
                        continue;
                    }

                    boolean granted = provider.evaluate(session, policy, adminUser);

                    if (Logic.NEGATIVE.equals(policy.getLogic())) {
                        granted = !granted;
                    }

                    if (granted) {
                        allowedIds.addAll(ids);
                    } else {
                        deniedIds.addAll(ids);
                    }
                }
            });
        }

        allowedIds.removeAll(deniedIds);

        if (allowedIds.contains(resourceType.getType())) {
            allowedIds.removeIf(not(resourceType.getType()::equals));
        }

        if (deniedIds.contains(resourceType.getType())) {
            deniedIds.removeIf(not(resourceType.getType()::equals));
        }

        return new PartialResourceEvaluationResult(resourceType, allowedIds, deniedIds);
    }

    private List<PartialEvaluationPolicyProvider> getPartialEvaluationPolicyProviders(KeycloakSession session) {
        return session.getAllProviders(PolicyProvider.class).stream()
                .filter(provider -> provider instanceof PartialEvaluationPolicyProvider)
                .map(PartialEvaluationPolicyProvider.class::cast)
                .toList();
    }

    private boolean skipPartialEvaluation(KeycloakSession session, UserModel user, RealmModel realm, ResourceType resourceType) {
        if (user == null) {
            return false;
        }

        String clientId;

        if (realm.getName().equals(Config.getAdminRealm())) {
            clientId = realm.getMasterAdminClient().getClientId();
        } else {
            ClientModel client = realm.getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);
            clientId = client == null ? null : client.getClientId();
        }

        // client probably removed when removing the realm
        ClientModel client = clientId == null ? null : session.clients().getClientByClientId(realm, clientId);

        if (client == null) {
            return true;
        }

        if (resourceType.equals(AdminPermissionsSchema.USERS) || resourceType.equals(AdminPermissionsSchema.GROUPS)) {
            return user.hasRole(client.getRole(AdminRoles.VIEW_USERS)) || user.hasRole(client.getRole(AdminRoles.MANAGE_USERS)) || !hasAnyQueryAdminRole(client, user);
        } else if (resourceType.equals(AdminPermissionsSchema.CLIENTS)) {
            return user.hasRole(client.getRole(AdminRoles.VIEW_CLIENTS)) || user.hasRole(client.getRole(AdminRoles.MANAGE_CLIENTS)) || !hasAnyQueryAdminRole(client, user);
        } else {
            return false;
        }
    }

    private boolean hasAnyQueryAdminRole(ClientModel client, UserModel user) {
        for (String adminRole : List.of(AdminRoles.QUERY_CLIENTS, AdminRoles.QUERY_GROUPS, AdminRoles.QUERY_USERS)) {
            RoleModel role = client.getRole(adminRole);

            if (user.hasRole(role)) {
                return true;
            }
        }

        return false;
    }
}

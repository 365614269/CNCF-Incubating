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

package org.keycloak.tests.admin.authz.fgap;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;

import jakarta.ws.rs.core.Response;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.keycloak.admin.client.resource.PermissionsResource;
import org.keycloak.admin.client.resource.PoliciesResource;
import org.keycloak.admin.client.resource.ScopePermissionsResource;
import org.keycloak.models.Constants;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.idm.authorization.AbstractPolicyRepresentation;
import org.keycloak.representations.idm.authorization.ClientPolicyRepresentation;
import org.keycloak.representations.idm.authorization.Logic;
import org.keycloak.representations.idm.authorization.ScopePermissionRepresentation;
import org.keycloak.representations.idm.authorization.UserPolicyRepresentation;
import org.keycloak.testframework.annotations.InjectClient;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.realm.ManagedClient;
import org.keycloak.testframework.realm.ManagedRealm;

public abstract class AbstractPermissionTest {

    @InjectRealm(config = RealmAdminPermissionsConfig.class)
    ManagedRealm realm;

    @InjectClient(attachTo = Constants.ADMIN_PERMISSIONS_CLIENT_ID)
    ManagedClient client;

    protected static PermissionsResource getPermissionsResource(ManagedClient client) {
        return client.admin().authorization().permissions();
    }

    protected PoliciesResource getPolicies() {
        return client.admin().authorization().policies();
    }

    protected static ScopePermissionsResource getScopePermissionsResource(ManagedClient client) {
        return getPermissionsResource(client).scope();
    }

    protected static void createPermission(ManagedClient client, ScopePermissionRepresentation permission) {
        createPermission(client, permission, Response.Status.CREATED);
    }

    protected static void createPermission(ManagedClient client, ScopePermissionRepresentation permission, Response.Status expected) {
        try (Response response = getScopePermissionsResource(client).create(permission)) {
            assertEquals(expected.getStatusCode(), response.getStatus());
        }
    }

    protected static class PermissionBuilder {
        private final ScopePermissionRepresentation permission;

        static PermissionBuilder create() {
            ScopePermissionRepresentation rep = new ScopePermissionRepresentation();
            rep.setName(KeycloakModelUtils.generateId());
            return new PermissionBuilder(rep);
        }

        private PermissionBuilder(ScopePermissionRepresentation rep) {
            this.permission = rep;
        }
        ScopePermissionRepresentation build() {
            return permission;
        }
        PermissionBuilder logic(Logic logic) {
            permission.setLogic(logic);
            return this;
        }
        PermissionBuilder name(String name) {
            permission.setName(name);
            return this;
        }
        PermissionBuilder resourceType(String resourceType) {
            permission.setResourceType(resourceType);
            return this;
        }
        PermissionBuilder scopes(Set<String> scopes) {
            permission.setScopes(scopes);
            return this;
        }
        PermissionBuilder resources(Set<String> resources) {
            permission.setResources(resources);
            return this;
        }
        PermissionBuilder addPolicies(List<String> policies) {
            policies.forEach(policy -> permission.addPolicy(policy));
            return this;
        }
    }

    protected static UserPolicyRepresentation createUserPolicy(ManagedRealm realm, ManagedClient client, String name, String userId) {
        return createUserPolicy(realm, client, name, userId, Logic.POSITIVE);
    }

    protected static UserPolicyRepresentation createUserPolicy(ManagedRealm realm, ManagedClient client, String name, String userId, Logic logic) {
        UserPolicyRepresentation policy = new UserPolicyRepresentation();
        policy.setName(name);
        policy.addUser(userId);
        policy.setLogic(logic);
        try (Response response = client.admin().authorization().policies().user().create(policy)) {
            assertThat(response.getStatus(), equalTo(Response.Status.CREATED.getStatusCode()));
            realm.cleanup().add(r -> {
                String policyId = r.clients().get(client.getId()).authorization().policies().user().findByName(name).getId();
                r.clients().get(client.getId()).authorization().policies().user().findById(policyId).remove();
            });
        }
        return policy;
    }

    protected static ClientPolicyRepresentation createClientPolicy(ManagedRealm realm, ManagedClient client, String name, String clientId) {
        ClientPolicyRepresentation policy = new ClientPolicyRepresentation();
        policy.setName(name);
        policy.addClient(clientId);
        policy.setLogic(Logic.POSITIVE);
        try (Response response = client.admin().authorization().policies().client().create(policy)) {
            assertThat(response.getStatus(), equalTo(Response.Status.CREATED.getStatusCode()));
            realm.cleanup().add(r -> {
                String policyId = r.clients().get(client.getId()).authorization().policies().client().findByName(name).getId();
                r.clients().get(client.getId()).authorization().policies().client().findById(policyId).remove();
            });
        }
        return policy;
    }

    protected static ScopePermissionRepresentation createAllPermission(ManagedClient client, String resourceType, AbstractPolicyRepresentation policy, Set<String> scopes) {
        ScopePermissionRepresentation permission = PermissionBuilder.create()
                .resourceType(resourceType)
                .scopes(scopes)
                .addPolicies(List.of(policy.getName()))
                .build();

        createPermission(client, permission);

        return permission;
    }

    protected ScopePermissionRepresentation createPermission(ManagedClient client, String resourceId, String resourceType, Set<String> scopes, AbstractPolicyRepresentation... policies) {
        return createPermission(client, Logic.POSITIVE, resourceId, resourceType, scopes, policies);
    }

    protected ScopePermissionRepresentation createPermission(ManagedClient client, Logic logic, String resourceId, String resourceType, Set<String> scopes, AbstractPolicyRepresentation... policies) {
        ScopePermissionRepresentation permission = PermissionBuilder.create()
                .logic(logic)
                .resourceType(resourceType)
                .scopes(scopes)
                .resources(Set.of(resourceId))
                .addPolicies(Arrays.stream(policies).map(AbstractPolicyRepresentation::getName).collect(Collectors.toList()))
                .build();

        createPermission(client, permission);

        return permission;
    }
}

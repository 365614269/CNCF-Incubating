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

package org.keycloak.tests.admin.authz.fgap;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ClientScopeResource;
import org.keycloak.admin.client.resource.ScopePermissionsResource;
import org.keycloak.authorization.AdminPermissionsSchema;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.UserPolicyRepresentation;
import org.keycloak.testframework.annotations.InjectAdminClient;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.util.ApiUtil;

import java.util.List;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.fail;
import static org.keycloak.authorization.AdminPermissionsSchema.MAP_ROLE;
import static org.keycloak.authorization.AdminPermissionsSchema.MAP_ROLES;
import static org.keycloak.authorization.AdminPermissionsSchema.MAP_ROLE_CLIENT_SCOPE;
import static org.keycloak.authorization.AdminPermissionsSchema.MAP_ROLE_COMPOSITE;
import static org.keycloak.authorization.AdminPermissionsSchema.VIEW;

@KeycloakIntegrationTest(config = KeycloakAdminPermissionsServerConfig.class)
public class RoleResourceTypeEvaluationTest extends AbstractPermissionTest {

    @InjectAdminClient(mode = InjectAdminClient.Mode.MANAGED_REALM, client = "myclient", user = "myadmin")
    Keycloak realmAdminClient;

    private final String rolesType = AdminPermissionsSchema.ROLES.getType();

    @AfterEach
    public void onAfter() {
        ScopePermissionsResource permissions = getScopePermissionsResource(client);

        permissions.findAll(null, null, null, -1, -1).forEach(p -> permissions.findById(p.getId()).remove());
    }

    @Test
    public void testMapRoleClientScopeAllRoles() {
        UserRepresentation myadmin = realm.admin().users().search("myadmin").get(0);
        ClientRepresentation myclient = realm.admin().clients().findByClientId("myclient").get(0);

        UserPolicyRepresentation onlyMyAdminUserPolicy = createUserPolicy(realm, client, "Only My Admin User Policy", myadmin.getId());
        // we need to be able to list client scopes
        createPermission(client, myclient.getId(), AdminPermissionsSchema.CLIENTS.getType(), Set.of(VIEW), onlyMyAdminUserPolicy);

        // create a client-scope
        ClientScopeRepresentation clientScope = new ClientScopeRepresentation();
        clientScope.setName("my-client-scope");
        clientScope.setProtocol("openid-connect");
        try (Response response = realm.admin().clientScopes().create(clientScope)) {
            assertThat(response.getStatus(), equalTo(Response.Status.CREATED.getStatusCode()));
            clientScope.setId(ApiUtil.handleCreatedResponse(response));
            realm.cleanup().add(r -> r.clientScopes().get(clientScope.getId()).remove());
        }

        // we don't have permissions to map roles to a client scope so the list of available roles should be empty
        ClientScopeResource clientScopeResource = realmAdminClient.realm(realm.getName()).clientScopes().get(clientScope.getId());
        List<RoleRepresentation> availableRoles = clientScopeResource.getScopeMappings().realmLevel().listAvailable();
        assertThat(availableRoles, empty());

        // grant the permission to map all roles to client scopes
        createAllPermission(client, rolesType, onlyMyAdminUserPolicy, Set.of(MAP_ROLE_CLIENT_SCOPE));

        availableRoles = clientScopeResource.getScopeMappings().realmLevel().listAvailable();
        assertThat(availableRoles, not(empty()));
    }

    @Test
    public void testMapCompositeRoleAllRoles() {
        UserRepresentation myadmin = realm.admin().users().search("myadmin").get(0);

        // create a role and sub-role
        RoleRepresentation role = new RoleRepresentation();
        role.setName("myRole");
        realm.admin().roles().create(role);
        realm.cleanup().add(r -> r.roles().get("myRole").remove());

        RoleRepresentation subRole = new RoleRepresentation();
        subRole.setName("mySubRole");
        realm.admin().roles().create(subRole);
        subRole = realm.admin().roles().get("mySubRole").toRepresentation();
        realm.cleanup().add(r -> r.roles().get("mySubRole").remove());

        // the following operation should fail as the permission wasn't granted yet
        try {
            realmAdminClient.realm(realm.getName()).roles().get("myRole").addComposites(List.of(subRole));
            fail("Expected exception wasn't thrown.");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(ForbiddenException.class));
        }

        String clientId = realm.admin().clients().findByClientId("realm-management").get(0).getId();
        RoleRepresentation manageRealmRole = realm.admin().clients().get(clientId).roles().get("manage-realm").toRepresentation();
        realm.admin().users().get(myadmin.getId()).roles().clientLevel(clientId).add(List.of(manageRealmRole));
        realmAdminClient.tokenManager().grantToken();

        UserPolicyRepresentation onlyMyAdminUserPolicy = createUserPolicy(realm, client, "Only My Admin User Policy", myadmin.getId());
        createAllPermission(client, rolesType, onlyMyAdminUserPolicy, Set.of(MAP_ROLE_COMPOSITE));

        realmAdminClient.realm(realm.getName()).roles().get("myRole").addComposites(List.of(subRole));
    }

    @Test
    public void testMapRoleOnlySpecificRole() {
        UserRepresentation myadmin = realm.admin().users().search("myadmin").get(0);

        // create some roles
        RoleRepresentation role = new RoleRepresentation();
        role.setName("myRole");
        realm.admin().roles().create(role);
        role = realm.admin().roles().get("myRole").toRepresentation();
        realm.cleanup().add(r -> r.roles().get("myRole").remove());

        RoleRepresentation otherRole = new RoleRepresentation();
        otherRole.setName("otherRole");
        realm.admin().roles().create(otherRole);
        otherRole = realm.admin().roles().get("otherRole").toRepresentation();
        realm.cleanup().add(r -> r.roles().get("otherRole").remove());

        // the following operation should fail as the permission wasn't granted yet
        try {
            realmAdminClient.realm(realm.getName()).users().get(myadmin.getId()).roles().realmLevel().add(List.of(role));
            fail("Expected exception wasn't thrown.");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(ForbiddenException.class));
        }

        // create required permissions
        UserPolicyRepresentation onlyMyAdminUserPolicy = createUserPolicy(realm, client, "Only My Admin User Policy", myadmin.getId());
        createPermission(client, role.getId(), rolesType, Set.of(MAP_ROLE), onlyMyAdminUserPolicy);
        createPermission(client, myadmin.getId(), AdminPermissionsSchema.USERS_RESOURCE_TYPE, Set.of(MAP_ROLES), onlyMyAdminUserPolicy);

        // should pass
        realmAdminClient.realm(realm.getName()).users().get(myadmin.getId()).roles().realmLevel().add(List.of(role));

        // the following operation should fail as there is no permission for "otherRole"
        try {
            realmAdminClient.realm(realm.getName()).users().get(myadmin.getId()).roles().realmLevel().add(List.of(otherRole));
            fail("Expected exception wasn't thrown.");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(ForbiddenException.class));
        }
    }
}

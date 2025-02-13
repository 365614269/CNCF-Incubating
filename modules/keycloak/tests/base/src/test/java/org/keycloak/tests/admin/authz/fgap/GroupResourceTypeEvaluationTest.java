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
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.keycloak.authorization.AdminPermissionsSchema.MANAGE;
import static org.keycloak.authorization.AdminPermissionsSchema.MANAGE_GROUP_MEMBERSHIP;
import static org.keycloak.authorization.AdminPermissionsSchema.MANAGE_MEMBERS;
import static org.keycloak.authorization.AdminPermissionsSchema.MANAGE_MEMBERSHIP;
import static org.keycloak.authorization.AdminPermissionsSchema.VIEW;
import static org.keycloak.authorization.AdminPermissionsSchema.VIEW_MEMBERS;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ScopePermissionsResource;
import org.keycloak.authorization.AdminPermissionsSchema;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.ScopePermissionRepresentation;
import org.keycloak.representations.idm.authorization.UserPolicyRepresentation;
import org.keycloak.testframework.annotations.InjectAdminClient;
import org.keycloak.testframework.annotations.InjectUser;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.realm.ManagedUser;
import org.keycloak.testframework.realm.UserConfigBuilder;
import org.keycloak.testframework.util.ApiUtil;

@KeycloakIntegrationTest(config = KeycloakAdminPermissionsServerConfig.class)
public class GroupResourceTypeEvaluationTest extends AbstractPermissionTest {

    @InjectUser(ref = "alice")
    ManagedUser userAlice;

    @InjectAdminClient(mode = InjectAdminClient.Mode.MANAGED_REALM, client = "myclient", user = "myadmin")
    Keycloak realmAdminClient;

    private final String groupName = "top_group";
    private final GroupRepresentation topGroup = new GroupRepresentation();;

    @BeforeEach // cannot use @BeforeAll, realm is not initializaed yet
    public void onBefore() {
        topGroup.setName(groupName);
        try (Response response = realm.admin().groups().add(topGroup)) {
            assertThat(response.getStatus(), equalTo(Response.Status.CREATED.getStatusCode()));
            topGroup.setId(ApiUtil.handleCreatedResponse(response));
            realm.cleanup().add(r -> r.groups().group(topGroup.getId()).remove());
        }
        realm.admin().users().get(userAlice.getId()).joinGroup(topGroup.getId());
    }

    @AfterEach
    public void onAfter() {
        ScopePermissionsResource permissions = getScopePermissionsResource(client);

        for (ScopePermissionRepresentation permission : permissions.findAll(null, null, null, -1, -1)) {
            permissions.findById(permission.getId()).remove();
        }
    }

    @Test
    public void testCanViewUserByViewGroupMembers() {
        UserRepresentation myadmin = realm.admin().users().search("myadmin").get(0);
        UserPolicyRepresentation allowMyAdminPermission = createUserPolicy(realm, client, "Only My Admin User Policy", myadmin.getId());

        // my admin should NOT be able to see Alice
        List<UserRepresentation> search = realmAdminClient.realm(realm.getName()).users().search(null, -1, -1);
        assertTrue(search.isEmpty());

        // allow my admin to view members of the group where Alice is member of
        createGroupPermission(topGroup, Set.of(VIEW_MEMBERS), allowMyAdminPermission);

        // my admin should be able to see Alice due to her membership and VIEW_MEMBERS permission
        search = realmAdminClient.realm(realm.getName()).users().search(null, -1, -1);
        assertEquals(1, search.size());
        assertEquals(userAlice.getUsername(), search.get(0).getUsername());
    }

    @Test
    public void testCanViewUserByManageGroupMembers() {
        UserRepresentation myadmin = realm.admin().users().search("myadmin").get(0);
        UserPolicyRepresentation allowMyAdminPermission = createUserPolicy(realm, client, "Only My Admin User Policy", myadmin.getId());

        // my admin should NOT be able to see Alice
        List<UserRepresentation> search = realmAdminClient.realm(realm.getName()).users().search(null, -1, -1);
        assertTrue(search.isEmpty());

        // my admin should not be able to manage yet
        try {
            realmAdminClient.realm(realm.getName()).users().get(userAlice.getId()).update(UserConfigBuilder.create().email("email@test.com").build());
            fail("Expected Exception wasn't thrown.");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(ForbiddenException.class));
        }

        // allow my admin to manage members of the group where Alice is member of
        createGroupPermission(topGroup, Set.of(MANAGE_MEMBERS), allowMyAdminPermission);

        // my admin should be able to see Alice due to her membership and MANAGE_MEMBERS permission
        search = realmAdminClient.realm(realm.getName()).users().search(null, -1, -1);
        assertEquals(1, search.size());
        assertEquals(userAlice.getUsername(), search.get(0).getUsername());

        // my admin should be able to update Alice due to her membership and MANAGE_MEMBERS permission
        realmAdminClient.realm(realm.getName()).users().get(userAlice.getId()).update(UserConfigBuilder.create().email("email@test.com").build());
        assertEquals("email@test.com", realmAdminClient.realm(realm.getName()).users().get(userAlice.getId()).toRepresentation().getEmail());
    }

    @Test
    public void testManageAllGroups() {
        // myadmin shouldn't be able to create groups just yet
        try (Response response = realmAdminClient.realm(realm.getName()).groups().add(new GroupRepresentation())) {
            assertEquals(Response.Status.FORBIDDEN.getStatusCode(), response.getStatus());
        }

        // myadmin shouldn't be able to add child for a group
        try (Response response = realmAdminClient.realm(realm.getName()).groups().group(topGroup.getId()).subGroup(new GroupRepresentation())) {
            assertEquals(Response.Status.FORBIDDEN.getStatusCode(), response.getStatus());
        }

        // myadmin shouldn't be able to map roles for group
        try {
            realmAdminClient.realm(realm.getName()).groups().group(topGroup.getId()).roles().realmLevel().add(List.of());
            fail("Expected Exception wasn't thrown.");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(ForbiddenException.class));
        }

        //create all-groups permission for "myadmin" (so that myadmin can manage all groups in the realm)
        UserPolicyRepresentation policy = createUserPolicy(realm, client, "Only My Admin User Policy", realm.admin().users().search("myadmin").get(0).getId());
        createAllGroupsPermission(policy, Set.of(MANAGE));

        // creating group requires manage scope
        GroupRepresentation group = new GroupRepresentation();
        group.setName("testGroup");
        String testGroupId = ApiUtil.handleCreatedResponse(realmAdminClient.realm(realm.getName()).groups().add(group));
        group.setId(testGroupId);

        // it should be possible to update the group due to fallback to all-groups permission
        group.setName("newGroup");
        realmAdminClient.realm(realm.getName()).groups().group(testGroupId).update(group);
        assertEquals("newGroup", realmAdminClient.realm(realm.getName()).groups().group(testGroupId).toRepresentation().getName());

        // it should be possible to add the child to the group now
        try (Response response = realmAdminClient.realm(realm.getName()).groups().group(topGroup.getId()).subGroup(group)) {
            assertEquals(Response.Status.NO_CONTENT.getStatusCode(), response.getStatus());
        }

        // it should be possible to map roles now
        // trying with non existent role as we need to test manage permission for groups (not `auth.roles().requireMapRole(roleModel);`)
        // expecting NotFoundException
        try {
            realmAdminClient.realm(realm.getName()).groups().group(topGroup.getId()).roles().realmLevel().add(List.of(new RoleRepresentation("non_existent", null, false)));
            fail("Expected Exception wasn't thrown.");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(NotFoundException.class));
        }
    }

    @Test
    public void testManageGroup() {
        // create group
        GroupRepresentation myGroup = new GroupRepresentation();
        myGroup.setName("my_group");

        try (Response response = realm.admin().groups().add(myGroup)) {
            assertThat(response.getStatus(), equalTo(Response.Status.CREATED.getStatusCode()));
            myGroup.setId(ApiUtil.handleCreatedResponse(response));
            realm.cleanup().add(r -> r.groups().group(myGroup.getId()).remove());
        }

        //create group permission for "myadmin" to manage the myGroup
        UserPolicyRepresentation policy = createUserPolicy(realm, client, "Only My Admin User Policy", realm.admin().users().search("myadmin").get(0).getId());
        createGroupPermission(myGroup, Set.of(MANAGE), policy);

        // myadmin shouldn't be able to update the topGroup
        try {
            realmAdminClient.realm(realm.getName()).groups().group(topGroup.getId()).update(myGroup);
            fail("Expected Exception wasn't thrown.");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(ForbiddenException.class));
        }

        // it should be possible to update the myGroup
        myGroup.setName("newGroup");
        realmAdminClient.realm(realm.getName()).groups().group(myGroup.getId()).update(myGroup);
        assertEquals("newGroup", realmAdminClient.realm(realm.getName()).groups().group(myGroup.getId()).toRepresentation().getName());

        // it should not be possible to add child to the topGroup
        GroupRepresentation subGroup = new GroupRepresentation();
        subGroup.setName("subGroup");
        try (Response response = realmAdminClient.realm(realm.getName()).groups().group(topGroup.getId()).subGroup(subGroup)) {
            assertEquals(Response.Status.FORBIDDEN.getStatusCode(), response.getStatus());
        }

        // it should be possible to add child to the myGroup
        try (Response response = realmAdminClient.realm(realm.getName()).groups().group(myGroup.getId()).subGroup(subGroup)) {
            assertEquals(Response.Status.CREATED.getStatusCode(), response.getStatus());
        }

        // it should not be possible to map roles to topGroup
        try {
            realmAdminClient.realm(realm.getName()).groups().group(topGroup.getId()).roles().realmLevel().add(List.of(new RoleRepresentation("non_existent", null, false)));
            fail("Expected Exception wasn't thrown.");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(ForbiddenException.class));
        }

        // it should be possible to map roles to myGroup
        // trying with non existent role as we need to test manage permission for groups (not `auth.roles().requireMapRole(roleModel);`)
        // expecting NotFoundException
        try {
            realmAdminClient.realm(realm.getName()).groups().group(myGroup.getId()).roles().realmLevel().add(List.of(new RoleRepresentation("non_existent", null, false)));
            fail("Expected Exception wasn't thrown.");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(NotFoundException.class));
        }
    }

    @Test
    public void testViewGroups() {
        UserPolicyRepresentation policy = createUserPolicy(realm, client, "Only My Admin User Policy", realm.admin().users().search("myadmin").get(0).getId());

        // should not see the groups
        List<GroupRepresentation> search = realmAdminClient.realm(realm.getName()).groups().groups();
        assertThat(search, hasSize(0));

        // create group
        GroupRepresentation myGroup = new GroupRepresentation();
        myGroup.setName("my_group");

        try (Response response = realm.admin().groups().add(myGroup)) {
            assertThat(response.getStatus(), equalTo(Response.Status.CREATED.getStatusCode()));
            myGroup.setId(ApiUtil.handleCreatedResponse(response));
            realm.cleanup().add(r -> r.groups().group(myGroup.getId()).remove());
        }

        //create permission to view myGroup
        createGroupPermission(myGroup, Set.of(VIEW), policy);

        // myadmin should be able to view only myGroup
        search = realmAdminClient.realm(realm.getName()).groups().groups();
        assertThat(search, hasSize(1));
        assertThat(search.get(0).getName(), equalTo(myGroup.getName()));

        // create view all groups permission for myadmin
        createAllGroupsPermission(policy, Set.of(VIEW));

        // now two groups should be returned (myGroup, topGroup)
        search = realmAdminClient.realm(realm.getName()).groups().groups();
        assertThat(search, hasSize(2));
    }

    @Test
    public void testManageGroupMembership() {
        // myadmin shouldn't be able to manage group membership of the user just yet
        try {
            realmAdminClient.realm(realm.getName()).users().get(userAlice.getId()).joinGroup("no-such");
            fail("Expected Exception wasn't thrown.");
        } catch (Exception ex) {
            assertThat(ex, instanceOf(ForbiddenException.class));
        }

        //create all-users permission for "myadmin" (so that myadmin can add users into a group)
        UserPolicyRepresentation policy = createUserPolicy(realm, client, "Only My Admin User Policy", realm.admin().users().search("myadmin").get(0).getId());
        createAllUserPermission(policy, Set.of(MANAGE_GROUP_MEMBERSHIP));

        //create group permission to allow manage membership for the group
        createGroupPermission(topGroup, Set.of(MANAGE_MEMBERSHIP), policy);

        
        //create new user
        String bobId = ApiUtil.handleCreatedResponse(realm.admin().users().create(UserConfigBuilder.create().username("bob").build()));
        realm.cleanup().add(r -> r.users().delete(bobId));

        //check myadmin can manage membership
        realmAdminClient.realm(realm.getName()).users().get(bobId).joinGroup(topGroup.getId());
    }

    private ScopePermissionRepresentation createAllGroupsPermission(UserPolicyRepresentation policy, Set<String> scopes) {
        return createAllPermission(client, AdminPermissionsSchema.GROUPS_RESOURCE_TYPE, policy, scopes);
    }

    private ScopePermissionRepresentation createAllUserPermission(UserPolicyRepresentation policy, Set<String> scopes) {
        return createAllPermission(client, AdminPermissionsSchema.USERS_RESOURCE_TYPE, policy, scopes);
    }

    private ScopePermissionRepresentation createGroupPermission(GroupRepresentation group, Set<String> scopes, UserPolicyRepresentation... policies) {
        return createPermission(client, group.getId(), AdminPermissionsSchema.GROUPS_RESOURCE_TYPE, scopes, policies);
    }
}

package org.keycloak.tests.admin.authz.fgap;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;

import jakarta.ws.rs.core.Response;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.ScopePermissionsResource;
import org.keycloak.authorization.AdminPermissionsSchema;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.authorization.GroupPolicyRepresentation;
import org.keycloak.representations.idm.authorization.GroupPolicyRepresentation.GroupDefinition;
import org.keycloak.representations.idm.authorization.Logic;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ScopePermissionRepresentation;
import org.keycloak.representations.idm.authorization.UserPolicyRepresentation;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.util.ApiUtil;

@KeycloakIntegrationTest(config = KeycloakAdminPermissionsServerConfig.class)
public class GroupResourceTypePermissionTest extends AbstractPermissionTest {

    @BeforeEach
    public void onBefore() {
        UserPolicyRepresentation policy = new UserPolicyRepresentation();
        policy.setName("User Policy");
        client.admin().authorization().policies().user().create(policy).close();
    }

    @AfterEach
    public void onAfter() {
        ScopePermissionsResource permissions = getScopePermissionsResource(client);

        for (ScopePermissionRepresentation permission : permissions.findAll(null, null, null, -1, -1)) {
            permissions.findById(permission.getId()).remove();
        }
    }
 
    @Test
    public void testRemoveGroup() {
        //create groups
        GroupRepresentation topGroup = new GroupRepresentation();
        topGroup.setName("topGroup");
        try (Response response = realm.admin().groups().add(topGroup)) {
            assertThat(response.getStatus(), equalTo(Response.Status.CREATED.getStatusCode()));
            topGroup.setId(ApiUtil.handleCreatedResponse(response));
            realm.cleanup().add(r -> r.groups().group(topGroup.getId()).remove());
        }
        GroupRepresentation topGroup1 = new GroupRepresentation();
        topGroup1.setName("topGroup1");
        try (Response response = realm.admin().groups().add(topGroup1)) {
            assertThat(response.getStatus(), equalTo(Response.Status.CREATED.getStatusCode()));
            topGroup1.setId(ApiUtil.handleCreatedResponse(response));
        }

        //create group policies
        createGroupPolicy("Only topGroup or topGroup1 Group Policy", topGroup.getId(), topGroup1.getId());
        createGroupPolicy("Only topGroup1 Group Policy", topGroup1.getId());

        //create group permissions
        createGroupPermission(topGroup, topGroup1);
        createGroupPermission(topGroup1);
        
        List<PolicyRepresentation> policies = getPolicies().policies(null, "Only", "group", null, null, null, null, null, null, null);
        assertThat(policies, hasSize(2));
        assertThat(policies.get(0).getConfig().get("groups"), containsString(topGroup1.getId()));
        assertThat(policies.get(1).getConfig().get("groups"), containsString(topGroup1.getId()));

        List<ScopePermissionRepresentation> permissions = getScopePermissionsResource(client).findAll(null, null, null, null, null);
        assertThat(permissions, hasSize(2));
        assertThat(getPolicies().policy(permissions.get(0).getId()).resources().stream().map(ResourceRepresentation::getName).collect(Collectors.toList()), hasItem(topGroup1.getId()));
        assertThat(getPolicies().policy(permissions.get(1).getId()).resources().stream().map(ResourceRepresentation::getName).collect(Collectors.toList()), hasItem(topGroup1.getId()));

        //remove group
        realm.admin().groups().group(topGroup1.getId()).remove();

        //check the resource was removed from policies
        GroupPolicyRepresentation groupPolicy = getPolicies().group().findByName("Only topGroup or topGroup1 Group Policy");
        assertThat(groupPolicy, notNullValue());
        Set<String> groupIds = groupPolicy.getGroups().stream().map(GroupDefinition::getId).collect(Collectors.toSet());
        assertThat(groupIds, not(contains(topGroup1.getId())));

        GroupPolicyRepresentation groupPolicy1 = getPolicies().group().findByName("Only topGroup1 Group Policy");
        assertThat(groupPolicy1, notNullValue());
        assertThat(groupPolicy1.getGroups().stream().map(GroupDefinition::getId).collect(Collectors.toSet()), empty());

        //there should be 1 permission left
        permissions = getScopePermissionsResource(client).findAll(null, null, null, null, null);
        assertThat(permissions, hasSize(1));
        assertThat(getPolicies().policy(permissions.get(0).getId()).resources().stream().map(ResourceRepresentation::getName).collect(Collectors.toList()), not(hasItem(topGroup1.getId())));
    }

    private ScopePermissionRepresentation createGroupPermission(GroupRepresentation... groups) {
        ScopePermissionRepresentation permission = PermissionBuilder.create()
                .resourceType(AdminPermissionsSchema.GROUPS.getType())
                .resources(Arrays.stream(groups).map(GroupRepresentation::getId).collect(Collectors.toSet()))
                .scopes(AdminPermissionsSchema.GROUPS.getScopes())
                .addPolicies(List.of("User Policy"))
                .build();

        createPermission(client, permission);

        return permission;
    }

    private GroupPolicyRepresentation createGroupPolicy(String name, String... groupIds) {
        GroupPolicyRepresentation policy = new GroupPolicyRepresentation();
        policy.setName(name);
        policy.addGroup(groupIds);
        policy.setLogic(Logic.POSITIVE);
        try (Response response = client.admin().authorization().policies().group().create(policy)) {
            assertThat(response.getStatus(), equalTo(Response.Status.CREATED.getStatusCode()));
            realm.cleanup().add(r -> {
                GroupPolicyRepresentation groupPolicy = client.admin().authorization().policies().group().findByName(name);
                if (groupPolicy != null) {
                    client.admin().authorization().policies().group().findById(groupPolicy.getId()).remove();
                }
            });
        }
        return policy;
    }
}

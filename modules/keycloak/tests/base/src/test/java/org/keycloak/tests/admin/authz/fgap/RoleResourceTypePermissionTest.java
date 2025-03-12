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
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.authorization.Logic;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.RolePolicyRepresentation;
import org.keycloak.representations.idm.authorization.RolePolicyRepresentation.RoleDefinition;
import org.keycloak.representations.idm.authorization.ScopePermissionRepresentation;
import org.keycloak.representations.idm.authorization.UserPolicyRepresentation;
import org.keycloak.testframework.annotations.InjectClient;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.realm.ManagedClient;

@KeycloakIntegrationTest(config = KeycloakAdminPermissionsServerConfig.class)
public class RoleResourceTypePermissionTest extends AbstractPermissionTest {

    @InjectClient(ref = "testClient")
    ManagedClient testClient;

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
    public void testRemoveRole() {
        //create roles
        RoleRepresentation realmRole = new RoleRepresentation();
        realmRole.setName("realmRole");
        try {
            realm.admin().roles().create(realmRole);
            realmRole.setId(realm.admin().roles().get(realmRole.getName()).toRepresentation().getId());
        } finally {
            realm.cleanup().add(r -> r.roles().deleteRole(realmRole.getName()));
        }

        RoleRepresentation clientRole = new RoleRepresentation();
        clientRole.setName("clientRole");
        clientRole.setClientRole(Boolean.TRUE);
        clientRole.setContainerId(testClient.getId());
        realm.admin().roles().create(clientRole);
        clientRole.setId(realm.admin().roles().get(clientRole.getName()).toRepresentation().getId());

        //create role policies
        createRolePolicy("Only realmRole or clientRole Role Policy", realmRole.getId(), clientRole.getId());
        createRolePolicy("Only clientRole Role Policy", clientRole.getId());

        //create role permissions
        createRolePermission(realmRole, clientRole);
        createRolePermission(clientRole);
        
        List<PolicyRepresentation> policies = getPolicies().policies(null, "Only", "role", null, null, null, null, null, null, null);
        assertThat(policies, hasSize(2));
        assertThat(policies.get(0).getConfig().get("roles"), containsString(clientRole.getId()));
        assertThat(policies.get(1).getConfig().get("roles"), containsString(clientRole.getId()));

        List<ScopePermissionRepresentation> permissions = getScopePermissionsResource(client).findAll(null, null, null, null, null);
        assertThat(permissions, hasSize(2));
        assertThat(getPolicies().policy(permissions.get(0).getId()).resources().stream().map(ResourceRepresentation::getName).collect(Collectors.toList()), hasItem(clientRole.getId()));
        assertThat(getPolicies().policy(permissions.get(1).getId()).resources().stream().map(ResourceRepresentation::getName).collect(Collectors.toList()), hasItem(clientRole.getId()));

        //remove role
        realm.admin().roles().get(clientRole.getName()).remove();

        //check the resource was removed from policies
        RolePolicyRepresentation rolePolicy = getPolicies().role().findByName("Only realmRole or clientRole Role Policy");
        assertThat(rolePolicy, notNullValue());
        Set<String> roleIds = rolePolicy.getRoles().stream().map(RoleDefinition::getId).collect(Collectors.toSet());
        assertThat(roleIds, not(contains(clientRole.getId())));

        RolePolicyRepresentation rolePolicy1 = getPolicies().role().findByName("Only clientRole Role Policy");
        assertThat(rolePolicy1, notNullValue());
        assertThat(rolePolicy1.getRoles().stream().map(RoleDefinition::getId).collect(Collectors.toSet()), empty());

        //there should be 1 permission left
        permissions = getScopePermissionsResource(client).findAll(null, null, null, null, null);
        assertThat(permissions, hasSize(1));
        assertThat(getPolicies().policy(permissions.get(0).getId()).resources().stream().map(ResourceRepresentation::getName).collect(Collectors.toList()), not(hasItem(clientRole.getId())));
    }

    private ScopePermissionRepresentation createRolePermission(RoleRepresentation... roles) {
        ScopePermissionRepresentation permission = PermissionBuilder.create()
                .resourceType(AdminPermissionsSchema.ROLES.getType())
                .resources(Arrays.stream(roles).map(RoleRepresentation::getId).collect(Collectors.toSet()))
                .scopes(AdminPermissionsSchema.ROLES.getScopes())
                .addPolicies(List.of("User Policy"))
                .build();

        createPermission(client, permission);

        return permission;
    }

    private RolePolicyRepresentation createRolePolicy(String name, String... roleIds) {
        RolePolicyRepresentation policy = new RolePolicyRepresentation();
        policy.setName(name);
        for (String roleId : roleIds) {
            policy.addRole(roleId);
        }
        policy.setLogic(Logic.POSITIVE);
        try (Response response = client.admin().authorization().policies().role().create(policy)) {
            assertThat(response.getStatus(), equalTo(Response.Status.CREATED.getStatusCode()));
            realm.cleanup().add(r -> {
                RolePolicyRepresentation rolePolicy = client.admin().authorization().policies().role().findByName(name);
                if (rolePolicy != null) {
                    client.admin().authorization().policies().role().findById(rolePolicy.getId()).remove();
                }
            });
        }
        return policy;
    }
}

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

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.Response;
import java.util.Set;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.notNullValue;
import org.junit.jupiter.api.Test;
import org.keycloak.authorization.AdminPermissionsSchema;
import org.keycloak.representations.idm.authorization.DecisionStrategy;
import org.keycloak.representations.idm.authorization.PolicyEnforcementMode;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ResourceServerRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.keycloak.testframework.annotations.InjectUser;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.realm.ManagedUser;

@KeycloakIntegrationTest(config = KeycloakAdminPermissionsServerConfig.class)
public class PermissionRESTTest extends AbstractPermissionTest {

    @InjectUser(ref = "alice")
    private ManagedUser userAlice;

    @Test
    public void resourceServerTest() {
        ResourceServerRepresentation rep = new ResourceServerRepresentation();
        rep.setPolicyEnforcementMode(PolicyEnforcementMode.DISABLED);
        rep.setDecisionStrategy(DecisionStrategy.CONSENSUS);

        try {
            client.admin().authorization().update(rep);
        } catch (Exception ex) {
            assertThat(ex, instanceOf(BadRequestException.class));
        }

        try {
            client.admin().authorization().exportSettings();
        } catch (Exception ex) {
            assertThat(ex, instanceOf(BadRequestException.class));
        }

        try {
            client.admin().authorization().importSettings(rep);
        } catch (Exception ex) {
            assertThat(ex, instanceOf(BadRequestException.class));
        }
    }

    @Test
    public void scopesTest() {
        ScopeRepresentation manage = client.admin().authorization().scopes().findByName("manage");
        assertThat(manage, notNullValue());

        ScopeRepresentation customScope = new ScopeRepresentation();
        customScope.setName("custom");

        try (Response response = client.admin().authorization().scopes().create(customScope)) {
            assertThat(response.getStatus(), equalTo(Response.Status.BAD_REQUEST.getStatusCode()));
        }

        try {
            client.admin().authorization().scopes().scope(manage.getId()).update(manage);
        } catch (Exception ex) {
            assertThat(ex, instanceOf(BadRequestException.class));
        }

        try {
            client.admin().authorization().scopes().scope(manage.getId()).remove();
        } catch (Exception ex) {
            assertThat(ex, instanceOf(BadRequestException.class));
        }
    }

    @Test
    public void resourcesTest() {
        ResourceRepresentation resourceRep = new ResourceRepresentation("resource-1", "manage");
        resourceRep.setType(AdminPermissionsSchema.USERS.getType());
        //it is not expected to create resources directly
        try (Response response = client.admin().authorization().resources().create(resourceRep)) {
            assertThat(response.getStatus(), equalTo(Response.Status.BAD_REQUEST.getStatusCode()));
        }
        
        ResourceRepresentation usersResource = client.admin().authorization().resources().searchByName(AdminPermissionsSchema.USERS.getType());
        assertThat(usersResource, notNullValue());

        // updates to 'all resource type' resources not expected
        try {
            client.admin().authorization().resources().resource(usersResource.getId()).update(resourceRep);
        } catch (Exception ex) {
            assertThat(ex, instanceOf(BadRequestException.class));
        }

        // deletes to 'all resource type' resources not expected
        try {
            client.admin().authorization().resources().resource(usersResource.getId()).remove();
        } catch (Exception ex) {
            assertThat(ex, instanceOf(BadRequestException.class));
        }

        // this should create a resource for userAlice
        createPermission(PermissionBuilder.create()
                .resourceType(AdminPermissionsSchema.USERS.getType())
                .resources(Set.of(userAlice.getUsername()))
                .scopes(AdminPermissionsSchema.USERS.getScopes())
                .build());

        // resourceName should equal to userAlice.getId() by design
        ResourceRepresentation userAliceResourceRep = client.admin().authorization().resources().searchByName(userAlice.getId());
        assertThat(userAliceResourceRep, notNullValue());
        String aliceResourceId = userAliceResourceRep.getId();

        // updates not expected 
        try {
            client.admin().authorization().resources().resource(aliceResourceId).update(userAliceResourceRep);
        } catch (Exception ex) {
            assertThat(ex, instanceOf(BadRequestException.class));
        }

        // delete not expected 
        try {
            client.admin().authorization().resources().resource(aliceResourceId).remove();
        } catch (Exception ex) {
            assertThat(ex, instanceOf(BadRequestException.class));
        }
    }

    @Test
    public void permissionsTest() {
        // no resourceType, valid scopes
        createPermission(PermissionBuilder.create()
                .scopes(AdminPermissionsSchema.USERS.getScopes())
                .build(), Response.Status.BAD_REQUEST);

        // valid resourceType, no scopes
        createPermission(PermissionBuilder.create()
                .resourceType(AdminPermissionsSchema.USERS.getType())
                .build(), Response.Status.BAD_REQUEST);

        // valid resourceType, non-existent scopes
        createPermission(PermissionBuilder.create()
                .resourceType(AdminPermissionsSchema.USERS.getType())
                .scopes(Set.of("edit", "write", "token-exchange"))
                .build(), Response.Status.BAD_REQUEST);
    }    
}

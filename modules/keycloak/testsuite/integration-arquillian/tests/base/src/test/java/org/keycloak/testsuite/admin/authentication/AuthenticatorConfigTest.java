/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.testsuite.admin.authentication;

import org.junit.Before;
import org.junit.Test;
import org.keycloak.authentication.authenticators.broker.IdpCreateUserIfUniqueAuthenticatorFactory;
import org.keycloak.authentication.authenticators.broker.IdpDetectExistingBrokerUserAuthenticatorFactory;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigInfoRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.util.AdminEventPaths;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AuthenticatorConfigTest extends AbstractAuthenticationTest {

    private String flowId;
    private String executionId;
    private String executionId2;

    @Before
    public void beforeConfigTest() {
        AuthenticationFlowRepresentation flowRep = newFlow("firstBrokerLogin2", "firstBrokerLogin2", "basic-flow", true, false);
        flowId = createFlow(flowRep);

        HashMap<String, Object> params = new HashMap<>();
        params.put("provider", IdpCreateUserIfUniqueAuthenticatorFactory.PROVIDER_ID);
        authMgmtResource.addExecution("firstBrokerLogin2", params);
        assertAdminEvents.assertEvent(testRealmId, OperationType.CREATE, AdminEventPaths.authAddExecutionPath("firstBrokerLogin2"), params, ResourceType.AUTH_EXECUTION);
        params.put("provider", IdpDetectExistingBrokerUserAuthenticatorFactory.PROVIDER_ID);
        authMgmtResource.addExecution("firstBrokerLogin2", params);
        assertAdminEvents.assertEvent(testRealmId, OperationType.CREATE, AdminEventPaths.authAddExecutionPath("firstBrokerLogin2"), params, ResourceType.AUTH_EXECUTION);

        List<AuthenticationExecutionInfoRepresentation> executionReps = authMgmtResource.getExecutions("firstBrokerLogin2");
        AuthenticationExecutionInfoRepresentation exec = findExecutionByProvider(IdpCreateUserIfUniqueAuthenticatorFactory.PROVIDER_ID, executionReps);
        Assert.assertNotNull(exec);
        executionId = exec.getId();
        exec = findExecutionByProvider(IdpDetectExistingBrokerUserAuthenticatorFactory.PROVIDER_ID, executionReps);
        Assert.assertNotNull(exec);
        executionId2 = exec.getId();
    }

    @Test
    public void testCreateConfigWithReservedChar() {
        AuthenticatorConfigRepresentation cfg = newConfig("f!oo", IdpCreateUserIfUniqueAuthenticatorFactory.REQUIRE_PASSWORD_UPDATE_AFTER_REGISTRATION, "true");
        Response resp = authMgmtResource.newExecutionConfig(executionId, cfg);
        Assert.assertEquals(400, resp.getStatus());
    }

    @Test
    public void testCreateConfig() {
        AuthenticatorConfigRepresentation cfg = newConfig("foo", IdpCreateUserIfUniqueAuthenticatorFactory.REQUIRE_PASSWORD_UPDATE_AFTER_REGISTRATION, "true");

        // Attempt to create config for non-existent execution
        try (Response response = authMgmtResource.newExecutionConfig("exec-id-doesnt-exists", cfg)) {
            Assert.assertEquals(404, response.getStatus());
        }

        // Create config success
        String cfgId = createConfig(executionId, cfg);

        // Assert found
        AuthenticatorConfigRepresentation cfgRep = authMgmtResource.getAuthenticatorConfig(cfgId);
        assertConfig(cfgRep, cfgId, "foo", IdpCreateUserIfUniqueAuthenticatorFactory.REQUIRE_PASSWORD_UPDATE_AFTER_REGISTRATION, "true");

        // Cleanup
        authMgmtResource.removeAuthenticatorConfig(cfgId);
        assertAdminEvents.assertEvent(testRealmId, OperationType.DELETE, AdminEventPaths.authExecutionConfigPath(cfgId), ResourceType.AUTHENTICATOR_CONFIG);
    }

    @Test (expected = BadRequestException.class)
    public void testUpdateConfigWithBadChar() {
        AuthenticatorConfigRepresentation cfg = newConfig("foo", IdpCreateUserIfUniqueAuthenticatorFactory.REQUIRE_PASSWORD_UPDATE_AFTER_REGISTRATION, "true");
        String cfgId = createConfig(executionId, cfg);
        AuthenticatorConfigRepresentation cfgRep = authMgmtResource.getAuthenticatorConfig(cfgId);
        
        cfgRep.setAlias("Bad@Char");
        authMgmtResource.updateAuthenticatorConfig(cfgRep.getId(), cfgRep);
    }
    
    @Test
    public void testUpdateConfig() {
        AuthenticatorConfigRepresentation cfg = newConfig("foo", IdpCreateUserIfUniqueAuthenticatorFactory.REQUIRE_PASSWORD_UPDATE_AFTER_REGISTRATION, "true");
        String cfgId = createConfig(executionId, cfg);
        final AuthenticatorConfigRepresentation cfgRepNonExistent = authMgmtResource.getAuthenticatorConfig(cfgId);

        // Try to update not existent config
        NotFoundException nfe = Assert.assertThrows(NotFoundException.class, () -> authMgmtResource.updateAuthenticatorConfig("not-existent", cfgRepNonExistent));
        Assert.assertEquals(404, nfe.getResponse().getStatus());

        // Assert nothing changed
        AuthenticatorConfigRepresentation cfgRep = authMgmtResource.getAuthenticatorConfig(cfgId);
        assertConfig(cfgRep, cfgId, "foo", IdpCreateUserIfUniqueAuthenticatorFactory.REQUIRE_PASSWORD_UPDATE_AFTER_REGISTRATION, "true");

        // Update success
        cfgRep.setAlias("foo2");
        cfgRep.getConfig().put("configKey2", "configValue2");
        authMgmtResource.updateAuthenticatorConfig(cfgRep.getId(), cfgRep);
        assertAdminEvents.assertEvent(testRealmId, OperationType.UPDATE, AdminEventPaths.authExecutionConfigPath(cfgId), cfgRep, ResourceType.AUTHENTICATOR_CONFIG);

        // Assert updated
        cfgRep = authMgmtResource.getAuthenticatorConfig(cfgRep.getId());
        assertConfig(cfgRep, cfgId, "foo2",
                IdpCreateUserIfUniqueAuthenticatorFactory.REQUIRE_PASSWORD_UPDATE_AFTER_REGISTRATION, "true",
                "configKey2", "configValue2");
    }


    @Test
    public void testRemoveConfig() {
        AuthenticatorConfigRepresentation cfg = newConfig("foo", IdpCreateUserIfUniqueAuthenticatorFactory.REQUIRE_PASSWORD_UPDATE_AFTER_REGISTRATION, "true");
        String cfgId = createConfig(executionId, cfg);
        AuthenticatorConfigRepresentation cfgRep = authMgmtResource.getAuthenticatorConfig(cfgId);

        // Assert execution has our config
        AuthenticationExecutionInfoRepresentation execution = findExecutionByProvider(
                IdpCreateUserIfUniqueAuthenticatorFactory.PROVIDER_ID, authMgmtResource.getExecutions("firstBrokerLogin2"));
        Assert.assertEquals(cfgRep.getId(), execution.getAuthenticationConfig());

        // Test remove not-existent
        NotFoundException nfe = Assert.assertThrows(NotFoundException.class, () -> authMgmtResource.removeAuthenticatorConfig("not-existent"));
        Assert.assertEquals(404, nfe.getResponse().getStatus());

        // Test remove our config
        authMgmtResource.removeAuthenticatorConfig(cfgId);
        assertAdminEvents.assertEvent(testRealmId, OperationType.DELETE, AdminEventPaths.authExecutionConfigPath(cfgId), ResourceType.AUTHENTICATOR_CONFIG);

        // Assert config not found
        nfe = Assert.assertThrows(NotFoundException.class, () -> authMgmtResource.getAuthenticatorConfig(cfgRep.getId()));
        Assert.assertEquals(404, nfe.getResponse().getStatus());

        // Assert execution doesn't have our config
        execution = findExecutionByProvider(
                IdpCreateUserIfUniqueAuthenticatorFactory.PROVIDER_ID, authMgmtResource.getExecutions("firstBrokerLogin2"));
        Assert.assertNull(execution.getAuthenticationConfig());
    }

    @Test
    public void testNullsafetyIterationOverProperties() {
        String providerId = "auth-cookie";
        String providerName = "Cookie";
        AuthenticatorConfigInfoRepresentation description = authMgmtResource.getAuthenticatorConfigDescription(providerId);

        Assert.assertEquals(providerName, description.getName());
        Assert.assertTrue(description.getProperties().isEmpty());
    }

    @Test
    public void testDuplicateAuthenticatorConfigAlias() {
        // create a config for step1
        AuthenticatorConfigRepresentation config1 = new AuthenticatorConfigRepresentation();
        config1.setAlias("test-config-1");
        config1.setConfig(Map.of("key", "value"));
        String config1Id = createConfig(executionId, config1);

        // create the same config name for step2, should fail
        try (Response response = authMgmtResource.newExecutionConfig(executionId2, config1)) {
            Assert.assertEquals(409, response.getStatus());
        }

        // create a config for step2
        AuthenticatorConfigRepresentation config2 = new AuthenticatorConfigRepresentation();
        config2.setAlias("test-config-2");
        config2.setConfig(Map.of("key", "value"));
        String config2Id = createConfig(executionId, config2);

        // create a new config for step1, config1 should be removed
        AuthenticatorConfigRepresentation config3 = new AuthenticatorConfigRepresentation();
        config3.setAlias("test-config-1-modified");
        config3.setConfig(Map.of("key", "value"));
        String tmpConfig3Id = createConfig(executionId, config3);
        NotFoundException nfe = Assert.assertThrows(NotFoundException.class, () -> authMgmtResource.getAuthenticatorConfig(config1Id));
        Assert.assertEquals(404, nfe.getResponse().getStatus());

        // create a new config with thew same name but that overwrites the previous one
        String config3Id = createConfig(executionId, config3);
        nfe = Assert.assertThrows(NotFoundException.class, () -> authMgmtResource.getAuthenticatorConfig(tmpConfig3Id));
        Assert.assertEquals(404, nfe.getResponse().getStatus());

        // delete execution step1, config3 should be removed
        authMgmtResource.removeExecution(executionId);
        assertAdminEvents.assertEvent(testRealmId, OperationType.DELETE, AdminEventPaths.authExecutionPath(executionId), ResourceType.AUTH_EXECUTION);
        nfe = Assert.assertThrows(NotFoundException.class, () -> authMgmtResource.getAuthenticatorConfig(config3Id));
        Assert.assertEquals(404, nfe.getResponse().getStatus());

        // remove flow, config and exec for step2 should be removed
        authMgmtResource.deleteFlow(flowId);
        assertAdminEvents.assertEvent(testRealmId, OperationType.DELETE, AdminEventPaths.authFlowPath(flowId), ResourceType.AUTH_FLOW);
        nfe = Assert.assertThrows(NotFoundException.class, () -> authMgmtResource.getExecution(executionId));
        Assert.assertEquals(404, nfe.getResponse().getStatus());
        nfe = Assert.assertThrows(NotFoundException.class, () -> authMgmtResource.getAuthenticatorConfig(config2Id));
        Assert.assertEquals(404, nfe.getResponse().getStatus());
    }

    private String createConfig(String executionId, AuthenticatorConfigRepresentation cfg) {
        try (Response resp = authMgmtResource.newExecutionConfig(executionId, cfg)) {
            Assert.assertEquals(201, resp.getStatus());
            String cfgId = ApiUtil.getCreatedId(resp);
            Assert.assertNotNull(cfgId);
            assertAdminEvents.assertEvent(testRealmId, OperationType.CREATE, AdminEventPaths.authAddExecutionConfigPath(executionId), cfg, ResourceType.AUTHENTICATOR_CONFIG);
            return cfgId;
        }
    }

    private AuthenticatorConfigRepresentation newConfig(String alias, String cfgKey, String cfgValue) {
        AuthenticatorConfigRepresentation cfg = new AuthenticatorConfigRepresentation();
        cfg.setAlias(alias);
        Map<String, String> cfgMap = new HashMap<>();
        cfgMap.put(cfgKey, cfgValue);
        cfg.setConfig(cfgMap);
        return cfg;
    }

    private void assertConfig(AuthenticatorConfigRepresentation cfgRep, String id, String alias, String... fields) {
        Assert.assertEquals(id, cfgRep.getId());
        Assert.assertEquals(alias, cfgRep.getAlias());
        Assert.assertMap(cfgRep.getConfig(), fields);
    }
}

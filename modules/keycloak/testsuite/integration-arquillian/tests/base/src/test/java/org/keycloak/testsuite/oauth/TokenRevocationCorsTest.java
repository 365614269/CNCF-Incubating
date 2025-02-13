/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.testsuite.oauth;

import static org.junit.Assert.*;
import static org.keycloak.testsuite.admin.AbstractAdminTest.*;

import java.io.IOException;
import java.util.List;

import jakarta.ws.rs.core.Response.Status;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.hamcrest.MatcherAssert;
import org.junit.Test;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.oidc.TokenMetadataRepresentation;
import org.keycloak.testsuite.AbstractKeycloakTest;
import org.keycloak.testsuite.util.ClientBuilder;
import org.keycloak.testsuite.util.Matchers;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.testsuite.util.oauth.TokenRevocationResponse;
import org.keycloak.util.JsonSerialization;

/**
 * @author <a href="mailto:yoshiyuki.tabata.jy@hitachi.com">Yoshiyuki Tabata</a>
 */
public class TokenRevocationCorsTest extends AbstractKeycloakTest {

    private static final String VALID_CORS_URL = "http://localtest.me:8180";
    private static final String INVALID_CORS_URL = "http://invalid.localtest.me:8180";

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        RealmRepresentation realm = loadJson(getClass().getResourceAsStream("/testrealm.json"), RealmRepresentation.class);
        realm.getClients().add(ClientBuilder.create().redirectUris(VALID_CORS_URL + "/realms/master/app")
            .addWebOrigin(VALID_CORS_URL).clientId("test-app2").publicClient().directAccessGrants().build());
        testRealms.add(realm);
    }

    @Test
    public void testTokenRevocationCorsRequestWithValidUrl() throws Exception {
        oauth.realm("test");
        oauth.clientId("test-app2");
        oauth.redirectUri(VALID_CORS_URL + "/realms/master/app");
        AccessTokenResponse tokenResponse = oauth.doGrantAccessTokenRequest(null, "test-user@localhost",
            "password");

        oauth.origin(VALID_CORS_URL);
        TokenRevocationResponse response = oauth.doTokenRevoke(tokenResponse.getRefreshToken(), "refresh_token", "password");
        assertTrue(response.isSuccess());
        assertCors(response);

        isTokenDisabled(tokenResponse, "test-app2");
    }

    @Test
    public void userTokenRevocationCorsRequestWithInvalidUrlShouldFail() throws Exception {
        oauth.realm("test");
        oauth.clientId("test-app2");
        oauth.redirectUri(VALID_CORS_URL + "/realms/master/app");
        AccessTokenResponse tokenResponse = oauth.doGrantAccessTokenRequest(null, "test-user@localhost",
            "password");

        oauth.origin(INVALID_CORS_URL);
        TokenRevocationResponse response = oauth.doTokenRevoke(tokenResponse.getRefreshToken(), "refresh_token", "password");
        assertTrue(response.isSuccess());
        assertNotCors(response);

        isTokenDisabled(tokenResponse, "test-app2");
    }

    private static void assertCors(TokenRevocationResponse response) {
        assertEquals("true", response.getHeader("Access-Control-Allow-Credentials"));
        assertEquals(VALID_CORS_URL, response.getHeader("Access-Control-Allow-Origin"));
        assertEquals("Access-Control-Allow-Methods", response.getHeader("Access-Control-Expose-Headers"));
    }

    private static void assertNotCors(TokenRevocationResponse response) {
        assertNull(response.getHeader("Access-Control-Allow-Credentials"));
        assertNull(response.getHeader("Access-Control-Allow-Origin"));
        assertNull(response.getHeader("Access-Control-Expose-Headers"));
    }

    private void isTokenDisabled(AccessTokenResponse tokenResponse, String clientId) throws IOException {
        String introspectionResponse = oauth.introspectAccessTokenWithClientCredential(clientId, "password",
            tokenResponse.getAccessToken());
        TokenMetadataRepresentation rep = JsonSerialization.readValue(introspectionResponse, TokenMetadataRepresentation.class);
        assertFalse(rep.isActive());

        oauth.clientId(clientId);
        AccessTokenResponse tokenRefreshResponse = oauth.doRefreshTokenRequest(tokenResponse.getRefreshToken(),
            "password");
        assertEquals(Status.BAD_REQUEST.getStatusCode(), tokenRefreshResponse.getStatusCode());
    }
}

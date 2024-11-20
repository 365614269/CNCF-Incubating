package org.keycloak.test.admin;

import org.junit.jupiter.api.Test;
import org.keycloak.TokenVerifier;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.crypto.Algorithm;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.test.framework.annotations.InjectAdminClient;
import org.keycloak.test.framework.annotations.InjectRealm;
import org.keycloak.test.framework.annotations.KeycloakIntegrationTest;
import org.keycloak.test.framework.realm.ManagedRealm;

import static org.junit.jupiter.api.Assertions.assertEquals;

@KeycloakIntegrationTest
public class AdminSignatureAlgorithmTest {

    @InjectAdminClient
    Keycloak admin;

    @InjectRealm(ref = "master", createRealm = false)
    ManagedRealm masterRealm;

    @Test
    public void changeRealmTokenAlgorithm() throws Exception {
        masterRealm.updateWithCleanup(r -> r.defaultSignatureAlgorithm(Algorithm.ES256));

        admin.tokenManager().invalidate(admin.tokenManager().getAccessTokenString());
        AccessTokenResponse accessToken = admin.tokenManager().getAccessToken();
        TokenVerifier<AccessToken> verifier = TokenVerifier.create(accessToken.getToken(), AccessToken.class);
        assertEquals(Algorithm.ES256, verifier.getHeader().getAlgorithm().name());
    }
}

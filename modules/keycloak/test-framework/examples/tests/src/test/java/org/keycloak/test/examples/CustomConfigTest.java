package org.keycloak.test.examples;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.common.Profile;
import org.keycloak.representations.info.FeatureRepresentation;
import org.keycloak.test.framework.annotations.InjectAdminClient;
import org.keycloak.test.framework.annotations.KeycloakIntegrationTest;
import org.keycloak.test.framework.server.KeycloakServerConfigBuilder;
import org.keycloak.test.framework.server.KeycloakServerConfig;

import java.util.Optional;

@KeycloakIntegrationTest(config = CustomConfigTest.CustomServerConfig.class)
public class CustomConfigTest {

    @InjectAdminClient
    Keycloak adminClient;

    @Test
    public void testUpdateEmailFeatureEnabled() {
        Optional<FeatureRepresentation> updateEmailFeature = adminClient.serverInfo().getInfo().getFeatures().stream().filter(f -> f.getName().equals(Profile.Feature.UPDATE_EMAIL.name())).findFirst();
        Assertions.assertTrue(updateEmailFeature.isPresent());
        Assertions.assertTrue(updateEmailFeature.get().isEnabled());
    }

    public static class CustomServerConfig implements KeycloakServerConfig {

        @Override
        public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
            return config.features(Profile.Feature.UPDATE_EMAIL);
        }

    }

}

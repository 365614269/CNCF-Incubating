package org.keycloak.test.framework.injection;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.test.framework.server.KeycloakServer;

import java.util.Map;

public class ValueTypeAliasTest {

    @Test
    public void withAlias() {
        ValueTypeAlias valueTypeAlias = new ValueTypeAlias();
        valueTypeAlias.addAll(Map.of(KeycloakServer.class, "server"));
        Assertions.assertEquals("server", valueTypeAlias.getAlias(KeycloakServer.class));
    }

    @Test
    public void withoutAlias() {
        Assertions.assertEquals("Keycloak", new ValueTypeAlias().getAlias(Keycloak.class));
    }

}

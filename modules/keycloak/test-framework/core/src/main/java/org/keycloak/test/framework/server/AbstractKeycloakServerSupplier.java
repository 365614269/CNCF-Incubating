package org.keycloak.test.framework.server;

import org.jboss.logging.Logger;
import org.keycloak.test.framework.injection.AbstractInterceptorHelper;
import org.keycloak.test.framework.annotations.KeycloakIntegrationTest;
import org.keycloak.test.framework.config.Config;
import org.keycloak.test.framework.database.TestDatabase;
import org.keycloak.test.framework.injection.InstanceContext;
import org.keycloak.test.framework.injection.LifeCycle;
import org.keycloak.test.framework.injection.Registry;
import org.keycloak.test.framework.injection.RequestedInstance;
import org.keycloak.test.framework.injection.Supplier;
import org.keycloak.test.framework.injection.SupplierHelpers;
import org.keycloak.test.framework.injection.SupplierOrder;

public abstract class AbstractKeycloakServerSupplier implements Supplier<KeycloakServer, KeycloakIntegrationTest> {

    @Override
    public Class<KeycloakServer> getValueType() {
        return KeycloakServer.class;
    }

    @Override
    public Class<KeycloakIntegrationTest> getAnnotationClass() {
        return KeycloakIntegrationTest.class;
    }

    @Override
    public KeycloakServer getValue(InstanceContext<KeycloakServer, KeycloakIntegrationTest> instanceContext) {
        KeycloakIntegrationTest annotation = instanceContext.getAnnotation();
        KeycloakServerConfig serverConfig = SupplierHelpers.getInstance(annotation.config());

        KeycloakServerConfigBuilder command = KeycloakServerConfigBuilder.startDev()
                .cache("local")
                .bootstrapAdminClient(Config.getAdminClientId(), Config.getAdminClientSecret());

        command.log().handlers(KeycloakServerConfigBuilder.LogHandlers.CONSOLE);

        command = serverConfig.configure(command);

        if (requiresDatabase()) {
            instanceContext.getDependency(TestDatabase.class);
        }

        ServerConfigInterceptorHelper interceptor = new ServerConfigInterceptorHelper(instanceContext.getRegistry());
        command = interceptor.intercept(command, instanceContext);

        command.log().fromConfig(Config.getConfig());

        getLogger().info("Starting Keycloak test server");
        if (getLogger().isDebugEnabled()) {
            getLogger().debugv("Startup command and options: \n\t{0}", String.join("\n\t", command.toArgs()));
        }

        long start = System.currentTimeMillis();

        KeycloakServer server = getServer();
        server.start(command);

        getLogger().infov("Keycloak test server started in {0} ms", System.currentTimeMillis() - start);

        return server;
    }

    @Override
    public LifeCycle getDefaultLifecycle() {
        return LifeCycle.GLOBAL;
    }

    @Override
    public boolean compatible(InstanceContext<KeycloakServer, KeycloakIntegrationTest> a, RequestedInstance<KeycloakServer, KeycloakIntegrationTest> b) {
        if (!a.getAnnotation().config().equals(b.getAnnotation().config())) {
            return false;
        }

        ServerConfigInterceptorHelper interceptor = new ServerConfigInterceptorHelper(a.getRegistry());
        return interceptor.sameInterceptors(a);
    }

    @Override
    public void close(InstanceContext<KeycloakServer, KeycloakIntegrationTest> instanceContext) {
        instanceContext.getValue().stop();
    }

    public abstract KeycloakServer getServer();

    public abstract boolean requiresDatabase();

    public abstract Logger getLogger();

    @Override
    public int order() {
        return SupplierOrder.KEYCLOAK_SERVER;
    }

    private static class ServerConfigInterceptorHelper extends AbstractInterceptorHelper<KeycloakServerConfigInterceptor, KeycloakServerConfigBuilder> {

        private ServerConfigInterceptorHelper(Registry registry) {
            super(registry, KeycloakServerConfigInterceptor.class);
        }

        @Override
        public KeycloakServerConfigBuilder intercept(KeycloakServerConfigBuilder value, Supplier<?, ?> supplier, InstanceContext<?, ?> existingInstance) {
            if (supplier instanceof KeycloakServerConfigInterceptor keycloakServerConfigInterceptor) {
                value = keycloakServerConfigInterceptor.intercept(value, existingInstance);
            }
            return value;
        }
    }

}

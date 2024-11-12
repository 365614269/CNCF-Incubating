package org.keycloak.test.framework.database;

import org.jboss.logging.Logger;
import org.testcontainers.containers.JdbcDatabaseContainer;
import org.testcontainers.containers.PostgreSQLContainer;

class PostgresTestDatabase extends AbstractContainerTestDatabase {

    private static final Logger LOGGER = Logger.getLogger(PostgresTestDatabase.class);

    public static final String NAME = "postgres";

    @Override
    public JdbcDatabaseContainer<?> createContainer() {
        return new PostgreSQLContainer<>(DatabaseProperties.getContainerImageName(NAME));
    }

    @Override
    public String getDatabaseVendor() {
        return NAME;
    }

    @Override
    public Logger getLogger() {
        return LOGGER;
    }
}

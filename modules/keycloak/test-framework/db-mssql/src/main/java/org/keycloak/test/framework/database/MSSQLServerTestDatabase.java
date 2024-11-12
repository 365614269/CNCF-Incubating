package org.keycloak.test.framework.database;

import org.jboss.logging.Logger;
import org.testcontainers.containers.JdbcDatabaseContainer;
import org.testcontainers.containers.MSSQLServerContainer;

import java.util.List;

class MSSQLServerTestDatabase extends AbstractContainerTestDatabase {

    private static final Logger LOGGER = Logger.getLogger(MSSQLServerTestDatabase.class);

    public static final String NAME = "mssql";

    @SuppressWarnings("resource")
    @Override
    public JdbcDatabaseContainer<?> createContainer() {
        return new MSSQLServerContainer<>(DatabaseProperties.getContainerImageName(NAME)).withPassword(getPassword()).withEnv("MSSQL_PID", "Express").acceptLicense();
    }

    @Override
    public void withDatabaseAndUser(String database, String username, String password) {
        // MSSQLServerContainer does not support withUsername and withDatabase
    }

    @Override
    public String getDatabaseVendor() {
        return NAME;
    }

    @Override
    public String getUsername() {
        return "sa";
    }

    @Override
    public String getPassword() {
        return "vEry$tron9Pwd";
    }

    @Override
    public List<String> getPostStartCommand() {
        return List.of("/opt/mssql-tools18/bin/sqlcmd", "-U", "sa", "-P", getPassword(), "-No", "-Q", "CREATE DATABASE " + getDatabase());
    }

    @Override
    public Logger getLogger() {
        return LOGGER;
    }
}

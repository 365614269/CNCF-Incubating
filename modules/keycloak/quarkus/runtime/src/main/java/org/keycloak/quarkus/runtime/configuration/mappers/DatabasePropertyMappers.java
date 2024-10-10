package org.keycloak.quarkus.runtime.configuration.mappers;

import io.quarkus.datasource.common.runtime.DatabaseKind;
import io.smallrye.config.ConfigSourceInterceptorContext;
import io.smallrye.config.ConfigValue;
import org.keycloak.config.DatabaseOptions;
import org.keycloak.config.database.Database;
import org.keycloak.quarkus.runtime.configuration.Configuration;

import static org.keycloak.quarkus.runtime.configuration.mappers.PropertyMapper.fromOption;

final class DatabasePropertyMappers {

    private DatabasePropertyMappers(){}

    public static PropertyMapper<?>[] getDatabasePropertyMappers() {
        return new PropertyMapper[] {
                fromOption(DatabaseOptions.DB_DIALECT)
                        .mapFrom(DatabaseOptions.DB, DatabasePropertyMappers::transformDialect)
                        .build(),
                fromOption(DatabaseOptions.DB_DRIVER)
                        .mapFrom(DatabaseOptions.DB, DatabasePropertyMappers::getXaOrNonXaDriver)
                        .to("quarkus.datasource.jdbc.driver")
                        .paramLabel("driver")
                        .build(),
                fromOption(DatabaseOptions.DB)
                        .to("quarkus.datasource.db-kind")
                        .transformer(DatabasePropertyMappers::toDatabaseKind)
                        .paramLabel("vendor")
                        .build(),
                fromOption(DatabaseOptions.DB_URL)
                        .to("quarkus.datasource.jdbc.url")
                        .mapFrom(DatabaseOptions.DB, DatabasePropertyMappers::getDatabaseUrl)
                        .paramLabel("jdbc-url")
                        .build(),
                fromOption(DatabaseOptions.DB_URL_HOST)
                        .to("kc.db-url-host")
                        .paramLabel("hostname")
                        .build(),
                fromOption(DatabaseOptions.DB_URL_DATABASE)
                        .to("kc.db-url-database")
                        .paramLabel("dbname")
                        .build(),
                fromOption(DatabaseOptions.DB_URL_PORT)
                        .to("kc.db-url-port")
                        .paramLabel("port")
                        .build(),
                fromOption(DatabaseOptions.DB_URL_PROPERTIES)
                        .to("kc.db-url-properties")
                        .paramLabel("properties")
                        .build(),
                fromOption(DatabaseOptions.DB_USERNAME)
                        .to("quarkus.datasource.username")
                        .transformer(DatabasePropertyMappers::resolveUsername)
                        .paramLabel("username")
                        .build(),
                fromOption(DatabaseOptions.DB_PASSWORD)
                        .to("quarkus.datasource.password")
                        .transformer(DatabasePropertyMappers::resolvePassword)
                        .paramLabel("password")
                        .isMasked(true)
                        .build(),
                fromOption(DatabaseOptions.DB_SCHEMA)
                        .paramLabel("schema")
                        .build(),
                fromOption(DatabaseOptions.DB_POOL_INITIAL_SIZE)
                        .to("quarkus.datasource.jdbc.initial-size")
                        .paramLabel("size")
                        .build(),
                fromOption(DatabaseOptions.DB_POOL_MIN_SIZE)
                        .to("quarkus.datasource.jdbc.min-size")
                        .paramLabel("size")
                        .build(),
                fromOption(DatabaseOptions.DB_POOL_MAX_SIZE)
                        .to("quarkus.datasource.jdbc.max-size")
                        .paramLabel("size")
                        .build()
        };
    }

    private static String getDatabaseUrl(String value, ConfigSourceInterceptorContext c) {
        return Database.getDefaultUrl(value).orElse(null);
    }

    private static String getXaOrNonXaDriver(String value, ConfigSourceInterceptorContext context) {
        ConfigValue xaEnabledConfigValue = context.proceed("kc.transaction-xa-enabled");
        boolean isXaEnabled = xaEnabledConfigValue != null && Boolean.parseBoolean(xaEnabledConfigValue.getValue());

        return Database.getDriver(value, isXaEnabled).orElse(null);
    }

    private static String toDatabaseKind(String db, ConfigSourceInterceptorContext context) {
        return Database.getDatabaseKind(db).orElse(null);
    }

    private static String resolveUsername(String value, ConfigSourceInterceptorContext context) {
        if (isDevModeDatabase(context)) {
            return "sa";
        }

        return value;
    }

    private static String resolvePassword(String value, ConfigSourceInterceptorContext context) {
        if (isDevModeDatabase(context)) {
            return "password";
        }

        return value;
    }

    private static boolean isDevModeDatabase(ConfigSourceInterceptorContext context) {
        String db = Configuration.getConfig().getConfigValue("kc.db").getValue();
        return Database.getDatabaseKind(db).get().equals(DatabaseKind.H2);
    }

    private static String transformDialect(String db, ConfigSourceInterceptorContext context) {
        return Database.getDialect(db).orElse(null);
    }

}

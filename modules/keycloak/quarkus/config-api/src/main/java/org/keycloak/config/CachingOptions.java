package org.keycloak.config;

import java.io.File;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.google.common.base.CaseFormat;

public class CachingOptions {

    public static final String CACHE_CONFIG_FILE_PROPERTY = "cache-config-file";

    private static final String CACHE_EMBEDDED_PREFIX = "cache-embedded";
    private static final String CACHE_EMBEDDED_MTLS_PREFIX = CACHE_EMBEDDED_PREFIX + "-mtls";
    public static final String CACHE_EMBEDDED_MTLS_ENABLED_PROPERTY = CACHE_EMBEDDED_MTLS_PREFIX + "-enabled";
    public static final String CACHE_EMBEDDED_MTLS_KEYSTORE_FILE_PROPERTY = CACHE_EMBEDDED_MTLS_PREFIX + "-key-store-file";
    public static final String CACHE_EMBEDDED_MTLS_KEYSTORE_PASSWORD_PROPERTY = CACHE_EMBEDDED_MTLS_PREFIX + "-key-store-password";
    public static final String CACHE_EMBEDDED_MTLS_TRUSTSTORE_FILE_PROPERTY = CACHE_EMBEDDED_MTLS_PREFIX + "-trust-store-file";
    public static final String CACHE_EMBEDDED_MTLS_TRUSTSTORE_PASSWORD_PROPERTY = CACHE_EMBEDDED_MTLS_PREFIX + "-trust-store-password";

    private static final String CACHE_REMOTE_PREFIX = "cache-remote";
    public static final String CACHE_REMOTE_HOST_PROPERTY = CACHE_REMOTE_PREFIX + "-host";
    public static final String CACHE_REMOTE_PORT_PROPERTY = CACHE_REMOTE_PREFIX + "-port";
    public static final String CACHE_REMOTE_USERNAME_PROPERTY = CACHE_REMOTE_PREFIX + "-username";
    public static final String CACHE_REMOTE_PASSWORD_PROPERTY = CACHE_REMOTE_PREFIX + "-password";
    public static final String CACHE_REMOTE_TLS_ENABLED_PROPERTY = CACHE_REMOTE_PREFIX + "-tls-enabled";

    private static final String CACHE_METRICS_PREFIX = "cache-metrics";
    public static final String CACHE_METRICS_HISTOGRAMS_ENABLED_PROPERTY = CACHE_METRICS_PREFIX + "-histograms-enabled";

    public static final String[] LOCAL_MAX_COUNT_CACHES = new String[]{"authorization", "keys", "realms", "users", };

    public static final String[] CLUSTERED_MAX_COUNT_CACHES = new String[]{"clientSessions", "offlineSessions", "offlineClientSessions", "sessions"};

    public enum Mechanism {
        ispn,
        local
    }

    public static final Option<Mechanism> CACHE = new OptionBuilder<>("cache", Mechanism.class)
            .category(OptionCategory.CACHE)
            .description("Defines the cache mechanism for high-availability. "
                    + "By default in production mode, a 'ispn' cache is used to create a cluster between multiple server nodes. "
                    + "By default in development mode, a 'local' cache disables clustering and is intended for development and testing purposes.")
            .defaultValue(Mechanism.ispn)
            .build();

    public enum Stack {
        tcp,
        udp,
        jdbc_ping,
        jdbc_ping_udp,
        kubernetes,
        ec2,
        azure,
        google;

        @Override
        public String toString() {
            return CaseFormat.LOWER_UNDERSCORE.to(CaseFormat.LOWER_HYPHEN, super.toString());
        }
    }

    public static final Option<Stack> CACHE_STACK = new OptionBuilder<>("cache-stack", Stack.class)
            .category(OptionCategory.CACHE)
            .strictExpectedValues(false)
            .description("Define the default stack to use for cluster communication and node discovery.")
            .defaultValue(Stack.jdbc_ping)
            .deprecatedValues(Stream.of(Stack.azure, Stack.ec2, Stack.google, Stack.tcp, Stack.udp, Stack.jdbc_ping_udp).map(Object::toString).collect(Collectors.toSet()), "Use 'jdbc-ping' instead")
            .build();

    public static final Option<File> CACHE_CONFIG_FILE = new OptionBuilder<>(CACHE_CONFIG_FILE_PROPERTY, File.class)
            .category(OptionCategory.CACHE)
            .description("Defines the file from which cache configuration should be loaded from. "
                    + "The configuration file is relative to the 'conf/' directory.")
            .build();

    public static final Option<Boolean> CACHE_EMBEDDED_MTLS_ENABLED = new OptionBuilder<>(CACHE_EMBEDDED_MTLS_ENABLED_PROPERTY, Boolean.class)
            .category(OptionCategory.CACHE)
            .description("Encrypts the network communication between Keycloak servers.")
            .defaultValue(Boolean.FALSE)
            .build();

    public static final Option<String> CACHE_EMBEDDED_MTLS_KEYSTORE = new OptionBuilder<>(CACHE_EMBEDDED_MTLS_KEYSTORE_FILE_PROPERTY, String.class)
            .category(OptionCategory.CACHE)
            .description("The Keystore file path. The Keystore must contain the certificate to use by the TLS protocol. " +
                    "By default, it lookup 'cache-mtls-keystore.p12' under conf/ directory.")
            .build();

    public static final Option<String> CACHE_EMBEDDED_MTLS_KEYSTORE_PASSWORD = new OptionBuilder<>(CACHE_EMBEDDED_MTLS_KEYSTORE_PASSWORD_PROPERTY, String.class)
            .category(OptionCategory.CACHE)
            .description("The password to access the Keystore.")
            .build();

    public static final Option<String> CACHE_EMBEDDED_MTLS_TRUSTSTORE = new OptionBuilder<>(CACHE_EMBEDDED_MTLS_TRUSTSTORE_FILE_PROPERTY, String.class)
            .category(OptionCategory.CACHE)
            .description("The Truststore file path. " +
                    "It should contain the trusted certificates or the Certificate Authority that signed the certificates. " +
                    "By default, it lookup 'cache-mtls-truststore.p12' under conf/ directory.")
            .build();

    public static final Option<String> CACHE_EMBEDDED_MTLS_TRUSTSTORE_PASSWORD = new OptionBuilder<>(CACHE_EMBEDDED_MTLS_TRUSTSTORE_PASSWORD_PROPERTY, String.class)
            .category(OptionCategory.CACHE)
            .description("The password to access the Truststore.")
            .build();

    public static final Option<String> CACHE_REMOTE_HOST = new OptionBuilder<>(CACHE_REMOTE_HOST_PROPERTY, String.class)
            .category(OptionCategory.CACHE)
            .description("The hostname of the external Infinispan cluster.")
            .build();

    public static final Option<Integer> CACHE_REMOTE_PORT = new OptionBuilder<>(CACHE_REMOTE_PORT_PROPERTY, Integer.class)
            .category(OptionCategory.CACHE)
            .description("The port of the external Infinispan cluster.")
            .defaultValue(11222)
            .build();

    public static final Option<String> CACHE_REMOTE_USERNAME = new OptionBuilder<>(CACHE_REMOTE_USERNAME_PROPERTY, String.class)
            .category(OptionCategory.CACHE)
            .description(String.format("The username for the authentication to the external Infinispan cluster. "
                            + "It is optional if connecting to an unsecure external Infinispan cluster. "
                            + "If the option is specified, '%s' is required as well.",
                    CACHE_REMOTE_PASSWORD_PROPERTY))
            .build();

    public static final Option<String> CACHE_REMOTE_PASSWORD = new OptionBuilder<>(CACHE_REMOTE_PASSWORD_PROPERTY, String.class)
            .category(OptionCategory.CACHE)
            .description(String.format("The password for the authentication to the external Infinispan cluster. "
                            + "It is optional if connecting to an unsecure external Infinispan cluster. "
                            + "If the option is specified, '%s' is required as well.",
                    CACHE_REMOTE_USERNAME_PROPERTY))
            .build();

    public static final Option<Boolean> CACHE_METRICS_HISTOGRAMS_ENABLED = new OptionBuilder<>(CACHE_METRICS_HISTOGRAMS_ENABLED_PROPERTY, Boolean.class)
            .category(OptionCategory.CACHE)
            .description("Enable histograms for metrics for the embedded caches.")
            .build();

    public static final Option<Boolean> CACHE_REMOTE_TLS_ENABLED = new OptionBuilder<>(CACHE_REMOTE_TLS_ENABLED_PROPERTY, Boolean.class)
            .category(OptionCategory.CACHE)
            .description("Enable TLS support to communicate with a secured remote Infinispan server. Recommended to be enabled in production.")
            .defaultValue(Boolean.TRUE)
            .build();

    public static Option<Integer> maxCountOption(String cache) {
        return new OptionBuilder<>(cacheMaxCountProperty(cache), Integer.class)
              .category(OptionCategory.CACHE)
              .description(String.format("The maximum number of entries that can be stored in-memory by the %s cache.", cache))
              .build();
    }

    public static String cacheMaxCountProperty(String cacheName) {
        cacheName = CaseFormat.LOWER_CAMEL.to(CaseFormat.LOWER_HYPHEN, cacheName);
        return String.format("%s-%s-max-count", CACHE_EMBEDDED_PREFIX, cacheName);
    }
}

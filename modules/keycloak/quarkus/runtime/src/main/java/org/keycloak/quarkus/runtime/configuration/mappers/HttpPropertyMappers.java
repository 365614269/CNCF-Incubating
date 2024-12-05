package org.keycloak.quarkus.runtime.configuration.mappers;

import io.quarkus.runtime.util.ClassPathUtils;
import io.quarkus.vertx.http.runtime.CertificateConfig;
import io.quarkus.vertx.http.runtime.options.TlsUtils;
import io.smallrye.config.ConfigSourceInterceptorContext;

import org.keycloak.common.crypto.FipsMode;
import org.keycloak.config.HttpOptions;
import org.keycloak.config.SecurityOptions;
import org.keycloak.quarkus.runtime.Environment;
import org.keycloak.quarkus.runtime.Messages;
import org.keycloak.quarkus.runtime.cli.PropertyException;
import org.keycloak.quarkus.runtime.configuration.Configuration;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Optional;

import static org.keycloak.quarkus.runtime.configuration.mappers.PropertyMapper.fromOption;

public final class HttpPropertyMappers {
    private static final int MIN_MAX_THREADS = 50;
    private static final String QUARKUS_HTTPS_CERT_FILES = "quarkus.http.ssl.certificate.files";
    private static final String QUARKUS_HTTPS_CERT_KEY_FILES = "quarkus.http.ssl.certificate.key-files";
    private static final String QUARKUS_HTTPS_KEY_STORE_FILE = "quarkus.http.ssl.certificate.key-store-file";
    private static final String QUARKUS_HTTPS_TRUST_STORE_FILE = "quarkus.http.ssl.certificate.trust-store-file";
    private static final String QUARKUS_HTTPS_TRUST_STORE_FILE_TYPE = "quarkus.http.ssl.certificate.trust-store-file-type";
    private static final String QUARKUS_HTTPS_KEY_STORE_FILE_TYPE = "quarkus.http.ssl.certificate.key-store-file-type";

    private HttpPropertyMappers(){}

    public static PropertyMapper<?>[] getHttpPropertyMappers() {
        return new PropertyMapper[] {
                fromOption(HttpOptions.HTTP_ENABLED)
                        .to("quarkus.http.insecure-requests")
                        .transformer(HttpPropertyMappers::getHttpEnabledTransformer)
                        .build(),
                fromOption(HttpOptions.HTTP_SERVER_ENABLED)
                        .to("quarkus.http.host-enabled")
                        .build(),
                fromOption(HttpOptions.HTTP_HOST)
                        .to("quarkus.http.host")
                        .paramLabel("host")
                        .build(),
                fromOption(HttpOptions.HTTP_RELATIVE_PATH)
                        .to("quarkus.http.root-path")
                        .paramLabel("path")
                        .build(),
                fromOption(HttpOptions.HTTP_PORT)
                        .to("quarkus.http.port")
                        .paramLabel("port")
                        .build(),
                fromOption(HttpOptions.HTTPS_PORT)
                        .to("quarkus.http.ssl-port")
                        .paramLabel("port")
                        .build(),
                fromOption(HttpOptions.HTTPS_CLIENT_AUTH)
                        .to("quarkus.http.ssl.client-auth")
                        .paramLabel("auth")
                        .build(),
                fromOption(HttpOptions.HTTPS_CIPHER_SUITES)
                        .to("quarkus.http.ssl.cipher-suites")
                        .paramLabel("ciphers")
                        .build(),
                fromOption(HttpOptions.HTTPS_PROTOCOLS)
                        .to("quarkus.http.ssl.protocols")
                        .paramLabel("protocols")
                        .build(),
                fromOption(HttpOptions.HTTPS_CERTIFICATES_RELOAD_PERIOD)
                        .to("quarkus.http.ssl.certificate.reload-period")
                        // -1 means no reload
                        .transformer((value, context) -> "-1".equals(value) ? null : value)
                        .paramLabel("reload period")
                        .build(),
                fromOption(HttpOptions.HTTPS_CERTIFICATE_FILE)
                        .to(QUARKUS_HTTPS_CERT_FILES)
                        .transformer(HttpPropertyMappers::transformPath)
                        .paramLabel("file")
                        .build(),
                fromOption(HttpOptions.HTTPS_CERTIFICATE_KEY_FILE)
                        .to(QUARKUS_HTTPS_CERT_KEY_FILES)
                        .transformer(HttpPropertyMappers::transformPath)
                        .paramLabel("file")
                        .build(),
                fromOption(HttpOptions.HTTPS_KEY_STORE_FILE
                        .withRuntimeSpecificDefault(getDefaultKeystorePathValue()))
                        .to(QUARKUS_HTTPS_KEY_STORE_FILE)
                        .transformer(HttpPropertyMappers::transformPath)
                        .paramLabel("file")
                        .build(),
                fromOption(HttpOptions.HTTPS_KEY_STORE_PASSWORD)
                        .to("quarkus.http.ssl.certificate.key-store-password")
                        .paramLabel("password")
                        .isMasked(true)
                        .build(),
                fromOption(HttpOptions.HTTPS_KEY_STORE_TYPE)
                        .mapFrom(SecurityOptions.FIPS_MODE, HttpPropertyMappers::resolveKeyStoreType)
                        .to(QUARKUS_HTTPS_KEY_STORE_FILE_TYPE)
                        .paramLabel("type")
                        .build(),
                fromOption(HttpOptions.HTTPS_TRUST_STORE_FILE)
                        .to(QUARKUS_HTTPS_TRUST_STORE_FILE)
                        .transformer(HttpPropertyMappers::transformPath)
                        .paramLabel("file")
                        .build(),
                fromOption(HttpOptions.HTTPS_TRUST_STORE_PASSWORD)
                        .to("quarkus.http.ssl.certificate.trust-store-password")
                        .paramLabel("password")
                        .isMasked(true)
                        .build(),
                fromOption(HttpOptions.HTTPS_TRUST_STORE_TYPE)
                        .mapFrom(SecurityOptions.FIPS_MODE, HttpPropertyMappers::resolveKeyStoreType)
                        .to(QUARKUS_HTTPS_TRUST_STORE_FILE_TYPE)
                        .transformer(HttpPropertyMappers::resolveKeyStoreType)
                        .paramLabel("type")
                        .build(),
                fromOption(HttpOptions.HTTP_MAX_QUEUED_REQUESTS)
                        .to("quarkus.thread-pool.queue-size")
                        .paramLabel("requests")
                        .build(),
                fromOption(HttpOptions.HTTP_POOL_MAX_THREADS)
                        .to("quarkus.thread-pool.max-threads")
                        .transformer(HttpPropertyMappers::resolveMaxThreads)
                        .paramLabel("threads")
                        .build(),
                fromOption(HttpOptions.HTTP_METRICS_HISTOGRAMS_ENABLED)
                        .isEnabled(MetricsPropertyMappers::metricsEnabled, MetricsPropertyMappers.METRICS_ENABLED_MSG)
                        .build(),
                fromOption(HttpOptions.HTTP_METRICS_SLOS)
                        .isEnabled(MetricsPropertyMappers::metricsEnabled, MetricsPropertyMappers.METRICS_ENABLED_MSG)
                        .paramLabel("list of buckets")
                        .build()
        };
    }

    public static void validateConfig() {
        boolean enabled = isHttpEnabled(Configuration.getOptionalKcValue(HttpOptions.HTTP_ENABLED.getKey()).orElse(null));
        Optional<String> certFile = Configuration.getOptionalValue(QUARKUS_HTTPS_CERT_FILES);
        Optional<String> keystoreFile = Configuration.getOptionalValue(QUARKUS_HTTPS_KEY_STORE_FILE);
        if (!enabled && certFile.isEmpty() && keystoreFile.isEmpty()) {
            throw new PropertyException(Messages.httpsConfigurationNotSet());
        }

        CertificateConfig config = new CertificateConfig();

        config.trustStoreFile = Configuration.getOptionalValue(QUARKUS_HTTPS_TRUST_STORE_FILE).map(Paths::get);
        config.trustStorePassword = Configuration.getOptionalKcValue(HttpOptions.HTTPS_TRUST_STORE_PASSWORD.getKey());
        config.trustStoreFileType = Configuration.getOptionalValue(QUARKUS_HTTPS_TRUST_STORE_FILE_TYPE);
        config.trustStoreProvider = Configuration.getOptionalValue("quarkus.http.ssl.certificate.trust-store-provider");
        config.trustStoreCertAlias = Configuration.getOptionalValue("quarkus.http.ssl.certificate.trust-store-cert-alias");
        config.trustStoreFiles = Optional.empty();

        config.keyStoreFile = keystoreFile.map(Paths::get);
        config.keyStorePassword = Configuration.getOptionalKcValue(HttpOptions.HTTPS_KEY_STORE_PASSWORD.getKey());
        config.keyStoreFileType = Configuration.getOptionalValue(QUARKUS_HTTPS_KEY_STORE_FILE_TYPE);
        config.keyStoreProvider = Configuration.getOptionalValue("quarkus.http.ssl.certificate.key-store-provider");
        config.keyStoreAlias = Configuration.getOptionalValue("quarkus.http.ssl.certificate.key-store-alias");
        config.keyStoreAliasPassword = Configuration.getOptionalValue("quarkus.http.ssl.certificate.key-store-alias-password");
        config.keyStoreAliasPasswordKey = Configuration.getOptionalValue("quarkus.http.ssl.certificate.key-store-alias-password-key");
        config.keyStoreKeyAlias = Configuration.getOptionalValue("quarkus.http.ssl.certificate.key-store-key-alias");
        
        config.keyFiles = Configuration.getOptionalValue(QUARKUS_HTTPS_CERT_KEY_FILES).map(Paths::get).map(List::of);
        config.files = certFile.map(Paths::get).map(List::of);

        try {
            TlsUtils.computeTrustOptions(config, config.trustStorePassword);
        } catch (IOException e) {
            throw new PropertyException("Failed to load 'https-trust-store' material: " + e.getClass().getSimpleName() + " " + e.getMessage(), e);
        } catch (IllegalArgumentException e) {
            if (e.getMessage().contains(QUARKUS_HTTPS_TRUST_STORE_FILE_TYPE)) {
                throw new PropertyException("Unable to determine 'https-trust-store-type' automatically. " +
                        "Adjust the file extension or specify the property.", e);
            }
            throw new PropertyException(e.getMessage(), e);
        }

        try {
            TlsUtils.computeKeyStoreOptions(config, config.keyStorePassword, config.keyStoreAliasPassword);
        } catch (IOException e) {
            throw new PropertyException("Failed to load 'https-key-' material: " + e.getClass().getSimpleName() + " " + e.getMessage(), e);
        } catch (IllegalArgumentException e) {
            if (e.getMessage().contains(QUARKUS_HTTPS_KEY_STORE_FILE_TYPE)) {
                throw new PropertyException("Unable to determine 'https-key-store-type' automatically. " +
                        "Adjust the file extension or specify the property.", e);
            }
            throw new PropertyException(e.getMessage(), e);
        }
    }

    private static String transformPath(String value, ConfigSourceInterceptorContext context) {
        return value == null ? value : ClassPathUtils.toResourceName(Path.of(value));
    }

    private static String getHttpEnabledTransformer(String value, ConfigSourceInterceptorContext context) {
        return isHttpEnabled(value) ? "enabled" : "disabled";
    }

    private static boolean isHttpEnabled(String value) {
        if (Environment.isDevMode() || Environment.isNonServerMode()) {
            return true;
        }
        return Boolean.parseBoolean(value);
    }

    private static File getDefaultKeystorePathValue() {
        String homeDir = Environment.getHomeDir();

        if (homeDir != null) {
            File file = Paths.get(homeDir, "conf", "server.keystore").toFile();

            if (file.exists()) {
                return file;
            }
        }

        return null;
    }

    private static String resolveKeyStoreType(String value,
            ConfigSourceInterceptorContext configSourceInterceptorContext) {
        if (FipsMode.STRICT.toString().equals(value)) {
            return "BCFKS";
        }
        return null;
    }

    private static String resolveMaxThreads(String value,
            ConfigSourceInterceptorContext configSourceInterceptorContext) {
        if (value == null) {
            return String.valueOf(Math.max(MIN_MAX_THREADS, 4 * Runtime.getRuntime().availableProcessors()));
        }
        return value;
    }
}


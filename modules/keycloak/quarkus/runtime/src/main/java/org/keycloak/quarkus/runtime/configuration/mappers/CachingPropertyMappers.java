package org.keycloak.quarkus.runtime.configuration.mappers;

import java.io.File;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.BooleanSupplier;

import io.smallrye.config.ConfigSourceInterceptorContext;
import org.keycloak.common.Profile;
import org.keycloak.config.CachingOptions;
import org.keycloak.config.Option;
import org.keycloak.infinispan.util.InfinispanUtils;
import org.keycloak.quarkus.runtime.Environment;
import org.keycloak.quarkus.runtime.cli.PropertyException;
import org.keycloak.quarkus.runtime.configuration.Configuration;
import org.keycloak.utils.StringUtil;

import static org.keycloak.quarkus.runtime.configuration.Configuration.getOptionalKcValue;
import static org.keycloak.quarkus.runtime.configuration.mappers.PropertyMapper.fromOption;

final class CachingPropertyMappers {

    private static final String REMOTE_HOST_SET = "remote host is set";
    private static final String MULTI_SITE_OR_EMBEDDED_REMOTE_FEATURE_SET = "feature '%s', '%s' or '%s' is set".formatted(Profile.Feature.MULTI_SITE.getKey(), Profile.Feature.CLUSTERLESS.getKey(), Profile.Feature.CACHE_EMBEDDED_REMOTE_STORE.getKey());
    private static final String MULTI_SITE_FEATURE_SET = "feature '%s' or '%s' is set".formatted(Profile.Feature.MULTI_SITE.getKey(), Profile.Feature.CLUSTERLESS.getKey());

    private static final String CACHE_STACK_SET_TO_ISPN = "'cache' type is set to '" + CachingOptions.Mechanism.ispn.name() + "'";

    private CachingPropertyMappers() {
    }

    public static PropertyMapper<?>[] getClusteringPropertyMappers() {
        List<PropertyMapper<?>> staticMappers = List.of(
                fromOption(CachingOptions.CACHE)
                        .paramLabel("type")
                        .build(),
                fromOption(CachingOptions.CACHE_STACK)
                        .isEnabled(CachingPropertyMappers::cacheSetToInfinispan, CACHE_STACK_SET_TO_ISPN)
                        .to("kc.spi-connections-infinispan-quarkus-stack")
                        .paramLabel("stack")
                        .build(),
                fromOption(CachingOptions.CACHE_CONFIG_FILE)
                        .mapFrom(CachingOptions.CACHE, (value, context) -> {
                            if (CachingOptions.Mechanism.local.name().equals(value)) {
                                return "cache-local.xml";
                            } else if (CachingOptions.Mechanism.ispn.name().equals(value)) {
                                return resolveConfigFile("cache-ispn.xml", null);
                            } else
                                return null;
                        })
                        .to("kc.spi-connections-infinispan-quarkus-config-file")
                        .transformer(CachingPropertyMappers::resolveConfigFile)
                        .paramLabel("file")
                        .build(),
                fromOption(CachingOptions.CACHE_EMBEDDED_MTLS_ENABLED)
                        .isEnabled(CachingPropertyMappers::getDefaultMtlsEnabled, "a TCP based cache-stack is used")
                        .build(),
                fromOption(CachingOptions.CACHE_EMBEDDED_MTLS_KEYSTORE.withRuntimeSpecificDefault(getDefaultKeystorePathValue()))
                        .paramLabel("file")
                        .isEnabled(() -> Configuration.isTrue(CachingOptions.CACHE_EMBEDDED_MTLS_ENABLED), "property '%s' is enabled".formatted(CachingOptions.CACHE_EMBEDDED_MTLS_ENABLED.getKey()))
                        .validator(value -> checkOptionPresent(CachingOptions.CACHE_EMBEDDED_MTLS_KEYSTORE, CachingOptions.CACHE_EMBEDDED_MTLS_KEYSTORE_PASSWORD))
                        .build(),
                fromOption(CachingOptions.CACHE_EMBEDDED_MTLS_KEYSTORE_PASSWORD)
                        .paramLabel("password")
                        .isMasked(true)
                        .isEnabled(() -> Configuration.isTrue(CachingOptions.CACHE_EMBEDDED_MTLS_ENABLED), "property '%s' is enabled".formatted(CachingOptions.CACHE_EMBEDDED_MTLS_ENABLED.getKey()))
                        .validator(value -> checkOptionPresent(CachingOptions.CACHE_EMBEDDED_MTLS_KEYSTORE_PASSWORD, CachingOptions.CACHE_EMBEDDED_MTLS_KEYSTORE))
                        .build(),
                fromOption(CachingOptions.CACHE_EMBEDDED_MTLS_TRUSTSTORE.withRuntimeSpecificDefault(getDefaultTruststorePathValue()))
                        .paramLabel("file")
                        .isEnabled(() -> Configuration.isTrue(CachingOptions.CACHE_EMBEDDED_MTLS_ENABLED), "property '%s' is enabled".formatted(CachingOptions.CACHE_EMBEDDED_MTLS_ENABLED.getKey()))
                        .validator(value -> checkOptionPresent(CachingOptions.CACHE_EMBEDDED_MTLS_TRUSTSTORE, CachingOptions.CACHE_EMBEDDED_MTLS_TRUSTSTORE_PASSWORD))
                        .build(),
                fromOption(CachingOptions.CACHE_EMBEDDED_MTLS_TRUSTSTORE_PASSWORD)
                        .paramLabel("password")
                        .isMasked(true)
                        .isEnabled(() -> Configuration.isTrue(CachingOptions.CACHE_EMBEDDED_MTLS_ENABLED), "property '%s' is enabled".formatted(CachingOptions.CACHE_EMBEDDED_MTLS_ENABLED.getKey()))
                        .validator(value -> checkOptionPresent(CachingOptions.CACHE_EMBEDDED_MTLS_TRUSTSTORE_PASSWORD, CachingOptions.CACHE_EMBEDDED_MTLS_TRUSTSTORE))
                        .build(),
                fromOption(CachingOptions.CACHE_EMBEDDED_MTLS_ROTATION)
                        .paramLabel("days")
                        .isEnabled(() -> Configuration.isTrue(CachingOptions.CACHE_EMBEDDED_MTLS_ENABLED), "property '%s' is enabled".formatted(CachingOptions.CACHE_EMBEDDED_MTLS_ENABLED.getKey()))
                        .validator(CachingPropertyMappers::validateCertificateRotationIsPositive)
                        .build(),
                fromOption(CachingOptions.CACHE_REMOTE_HOST)
                        .paramLabel("hostname")
                        .addValidateEnabled(CachingPropertyMappers::isRemoteCacheHostEnabled, MULTI_SITE_OR_EMBEDDED_REMOTE_FEATURE_SET)
                        .isRequired(InfinispanUtils::isRemoteInfinispan, MULTI_SITE_FEATURE_SET)
                        .build(),
                fromOption(CachingOptions.CACHE_REMOTE_PORT)
                        .isEnabled(CachingPropertyMappers::remoteHostSet, CachingPropertyMappers.REMOTE_HOST_SET)
                        .paramLabel("port")
                        .build(),
                fromOption(CachingOptions.CACHE_REMOTE_TLS_ENABLED)
                        .isEnabled(CachingPropertyMappers::remoteHostSet, CachingPropertyMappers.REMOTE_HOST_SET)
                        .build(),
                fromOption(CachingOptions.CACHE_REMOTE_USERNAME)
                        .isEnabled(CachingPropertyMappers::remoteHostSet, CachingPropertyMappers.REMOTE_HOST_SET)
                        .validator((value) -> validateCachingOptionIsPresent(CachingOptions.CACHE_REMOTE_USERNAME, CachingOptions.CACHE_REMOTE_PASSWORD))
                        .paramLabel("username")
                        .build(),
                fromOption(CachingOptions.CACHE_REMOTE_PASSWORD)
                        .isEnabled(CachingPropertyMappers::remoteHostSet, CachingPropertyMappers.REMOTE_HOST_SET)
                        .validator((value) -> validateCachingOptionIsPresent(CachingOptions.CACHE_REMOTE_PASSWORD, CachingOptions.CACHE_REMOTE_USERNAME))
                        .paramLabel("password")
                        .isMasked(true)
                        .build(),
                fromOption(CachingOptions.CACHE_METRICS_HISTOGRAMS_ENABLED)
                        .isEnabled(MetricsPropertyMappers::metricsEnabled, MetricsPropertyMappers.METRICS_ENABLED_MSG)
                        .build()
        );

        int numMappers = staticMappers.size() + CachingOptions.LOCAL_MAX_COUNT_CACHES.length + CachingOptions.CLUSTERED_MAX_COUNT_CACHES.length;
        List<PropertyMapper<?>> mappers = new ArrayList<>(numMappers);
        mappers.addAll(staticMappers);

        for (String cache : CachingOptions.LOCAL_MAX_COUNT_CACHES)
            mappers.add(maxCountOpt(cache, () -> true, ""));

        for (String cache : CachingOptions.CLUSTERED_MAX_COUNT_CACHES)
            mappers.add(maxCountOpt(cache, InfinispanUtils::isEmbeddedInfinispan, "embedded Infinispan clusters configured"));

        return mappers.toArray(new PropertyMapper[0]);
    }

    private static boolean getDefaultMtlsEnabled() {
        if (!cacheSetToInfinispan()) {
            return false;
        }
        Optional<String> cacheStackOptional = getOptionalKcValue(CachingOptions.CACHE_STACK);
        if (cacheStackOptional.isEmpty()) {
            return true;
        }
        String cacheStack = cacheStackOptional.get();
        return !(cacheStack.equals("udp") || cacheStack.equals("jdbc-ping-udp"));
    }

    private static boolean remoteHostSet() {
        return getOptionalKcValue(CachingOptions.CACHE_REMOTE_HOST_PROPERTY).isPresent();
    }

    private static boolean cacheSetToInfinispan() {
        if (InfinispanUtils.isRemoteInfinispan()) {
            return false;
        }

        Optional<String> cache = getOptionalKcValue(CachingOptions.CACHE);
        if (cache.isEmpty() && !Environment.isDevMode()) {
            return true;
        }
        return cache.isPresent() && cache.get().equals(CachingOptions.Mechanism.ispn.name());
    }

    private static String resolveConfigFile(String value, ConfigSourceInterceptorContext context) {
        String homeDir = Environment.getHomeDir();

        return homeDir == null ?
                value :
                homeDir + File.separator + "conf" + File.separator + value;
    }

    private static String getDefaultKeystorePathValue() {
        String homeDir = Environment.getHomeDir();

        if (homeDir != null) {
            File file = Paths.get(homeDir, "conf", "cache-mtls-keystore.p12").toFile();

            if (file.exists()) {
                return file.getAbsolutePath();
            }
        }

        return null;
    }

    private static String getDefaultTruststorePathValue() {
        String homeDir = Environment.getHomeDir();

        if (homeDir != null) {
            File file = Paths.get(homeDir, "conf", "cache-mtls-truststore.p12").toFile();

            if (file.exists()) {
                return file.getAbsolutePath();
            }
        }

        return null;
    }

    private static PropertyMapper<?> maxCountOpt(String cacheName, BooleanSupplier isEnabled, String enabledWhen) {
        return fromOption(CachingOptions.maxCountOption(cacheName))
                .isEnabled(isEnabled, enabledWhen)
                .paramLabel("max-count")
                .build();
    }

    private static boolean isRemoteCacheHostEnabled() {
        return InfinispanUtils.isRemoteInfinispan() || Profile.isFeatureEnabled(Profile.Feature.CACHE_EMBEDDED_REMOTE_STORE);
    }

    private static void validateCachingOptionIsPresent(Option<?> optionSet, Option<?> optionRequired) {
        if (getOptionalKcValue(optionRequired).isEmpty()) {
            throw new PropertyException("The option '%s' is required when '%s' is set.".formatted(optionRequired.getKey(), optionSet.getKey()));
        }
    }

    private static void checkOptionPresent(Option<String> option, Option<String> requiredOption) {
        if (getOptionalKcValue(requiredOption).isPresent()) {
            return;
        }
        throw new PropertyException("The option '%s' requires '%s' to be enabled.".formatted(option.getKey(), requiredOption.getKey()));
    }

    private static void validateCertificateRotationIsPositive(String value) {
        value = value.trim();
        if (StringUtil.isBlank(value)) {
            throw new PropertyException("Option '%s' must not be empty.".formatted(CachingOptions.CACHE_EMBEDDED_MTLS_ROTATION.getKey()));
        }
        try {
            if (Integer.parseInt(value) <= 0) {
                throw new NumberFormatException();
            }
        } catch (NumberFormatException unused) {
            throw new PropertyException("JGroups MTLS certificate rotation in '%s' option must positive.".formatted(CachingOptions.CACHE_EMBEDDED_MTLS_ROTATION.getKey()));
        }
    }
}

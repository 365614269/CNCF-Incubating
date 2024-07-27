/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.quarkus.runtime.configuration.test;

import io.quarkus.runtime.LaunchMode;
import io.quarkus.runtime.configuration.ConfigUtils;
import io.smallrye.config.ConfigValue;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigProviderResolver;
import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.config.spi.ConfigProviderResolver;
import org.junit.After;
import org.keycloak.Config;
import org.keycloak.quarkus.runtime.configuration.Configuration;
import org.keycloak.quarkus.runtime.configuration.KeycloakConfigSourceProvider;
import org.keycloak.quarkus.runtime.configuration.MicroProfileConfigProvider;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.function.Function;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

public abstract class AbstractConfigurationTest {

    private static final Properties SYSTEM_PROPERTIES = (Properties) System.getProperties().clone();
    private static final Map<String, String> ENVIRONMENT_VARIABLES = new HashMap<>(System.getenv());

    @SuppressWarnings("unchecked")
    public static void putEnvVar(String name, String value) {
        Map<String, String> env = System.getenv();
        Field field = null;
        try {
            field = env.getClass().getDeclaredField("m");
            field.setAccessible(true);
            ((Map<String, String>) field.get(env)).put(name, value);
        } catch (Exception cause) {
            throw new RuntimeException("Failed to update environment variables", cause);
        } finally {
            if (field != null) {
                field.setAccessible(false);
            }
        }
    }

    public static void putEnvVars(Map<String, String> map) {
        map.forEach(ConfigurationTest::putEnvVar);
    }

    @SuppressWarnings("unchecked")
    public static void removeEnvVar(String name) {
        Map<String, String> env = System.getenv();
        Field field = null;
        try {
            field = env.getClass().getDeclaredField("m");
            field.setAccessible(true);
            ((Map<String, String>) field.get(env)).remove(name);
        } catch (Exception cause) {
            throw new RuntimeException("Failed to update environment variables", cause);
        } finally {
            if (field != null) {
                field.setAccessible(false);
            }
        }
    }

    public static void setSystemProperty(String key, String value, Runnable runnable) {
        System.setProperty(key, value);
        try {
            runnable.run();
        } finally {
            System.clearProperty(key);
        }
    }

    @After
    public void onAfter() {
        Properties current = System.getProperties();

        for (String name : current.stringPropertyNames()) {
            if (!SYSTEM_PROPERTIES.containsKey(name)) {
                current.remove(name);
            }
        }

        for (String name : new HashMap<>(System.getenv()).keySet()) {
            if (!ENVIRONMENT_VARIABLES.containsKey(name)) {
                removeEnvVar(name);
            }
        }

        SmallRyeConfigProviderResolver.class.cast(ConfigProviderResolver.instance()).releaseConfig(ConfigProvider.getConfig());
    }

    protected Config.Scope initConfig(String... scope) {
        Config.init(new MicroProfileConfigProvider(createConfig()));
        return Config.scope(scope);
    }

    protected SmallRyeConfig createConfig() {
        KeycloakConfigSourceProvider.reload();
        // older versions of quarkus implicitly picked up this config, now we
        // must set it manually
        SmallRyeConfig config = ConfigUtils.configBuilder(true, LaunchMode.NORMAL).build();
        SmallRyeConfigProviderResolver resolver = new SmallRyeConfigProviderResolver();
        resolver.registerConfig(config, Thread.currentThread().getContextClassLoader());
        ConfigProviderResolver.setInstance(resolver);
        return config;
    }

    protected void assertConfig(String key, String expectedValue, boolean isExternal) {
        Function<String, ConfigValue> getConfig = isExternal ? Configuration::getConfigValue : Configuration::getKcConfigValue;
        var value = getConfig.apply(key).getValue();
        assertThat(String.format("Value is null for key '%s'", key), value, notNullValue());
        assertThat(String.format("Different value for key '%s'", key), value, is(expectedValue));
    }

    protected void assertConfig(String key, String expectedValue) {
        assertConfig(key, expectedValue, false);
    }

    protected void assertConfig(Map<String, String> expectedValues) {
        expectedValues.forEach(this::assertConfig);
    }

    protected void assertExternalConfig(String key, String expectedValue) {
        assertConfig(key, expectedValue, true);
    }

    protected void assertExternalConfig(Map<String, String> expectedValues) {
        expectedValues.forEach(this::assertExternalConfig);
    }
}

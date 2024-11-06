/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.quarkus.runtime.cli.command;

import static org.keycloak.quarkus.runtime.configuration.Configuration.getConfigValue;
import static org.keycloak.quarkus.runtime.configuration.Configuration.getPropertyNames;
import static org.keycloak.quarkus.runtime.configuration.mappers.PropertyMappers.maskValue;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.keycloak.quarkus.runtime.Environment;
import org.keycloak.quarkus.runtime.configuration.KeycloakConfigSourceProvider;
import org.keycloak.quarkus.runtime.configuration.MicroProfileConfigProvider;
import org.keycloak.quarkus.runtime.configuration.mappers.PropertyMapper;
import org.keycloak.quarkus.runtime.configuration.mappers.PropertyMappers;

import io.quarkus.runtime.Quarkus;
import io.smallrye.config.ConfigValue;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

@Command(name = "show-config",
        header = "Print out the current configuration.",
        description = "%nPrint out the current configuration.")
public final class ShowConfig extends AbstractCommand implements Runnable {

    public static final String NAME = "show-config";
    private static final List<String> allowedSystemPropertyKeys = List.of(
            "kc.version");

    @Parameters(
            paramLabel = "filter",
            defaultValue = "none",
            description = "Show all configuration options. Use 'all' to show all options.")
    String filter;

    @Override
    public void run() {
        String profile = Environment.updateProfile(true);

        Map<String, Set<String>> properties = getPropertiesByGroup();
        printRunTimeConfig(properties, profile);

        if (filter.equalsIgnoreCase("all")) {
            spec.commandLine().getOut().println("Quarkus Configuration:");
            properties.get(MicroProfileConfigProvider.NS_QUARKUS).stream().sorted()
                    .forEachOrdered(this::printProperty);
        }

        Quarkus.asyncExit(0);
    }

    private void printRunTimeConfig(Map<String, Set<String>> properties, String profile) {
        Set<String> uniqueNames = new HashSet<>();

        spec.commandLine().getOut().printf("Current Mode: %s%n", Environment.getKeycloakModeFromProfile(profile));

        spec.commandLine().getOut().println("Current Configuration:");

        properties.get(MicroProfileConfigProvider.NS_KEYCLOAK).stream().sorted()
                .filter(uniqueNames::add)
                .forEachOrdered(this::printProperty);
    }

    private static Map<String, Set<String>> getPropertiesByGroup() {
        Map<String, Set<String>> properties = StreamSupport
                .stream(getPropertyNames().spliterator(), false)
                .filter(ShowConfig::filterByGroup)
                .collect(Collectors.groupingBy(ShowConfig::groupProperties, Collectors.toSet()));

        return properties;
    }

    private void printProperty(String property) {
        ConfigValue configValue = getConfigValue(property);

        if (configValue.getValue() == null) {
            return;
        }

        if (configValue.getSourceName() == null) {
            return;
        }

        String value = configValue.getRawValue();

        if (value == null) {
            value = configValue.getValue();
        }

        PropertyMapper<?> mapper = PropertyMappers.getMapper(property);

        if (mapper == null && configValue.getSourceName().equals("SysPropConfigSource") && !allowedSystemPropertyKeys.contains(property)) {
            return; // most system properties are internally used, and not relevant during show-config
        }

        value = maskValue(configValue.getName(), value, configValue.getConfigSourceName());

        spec.commandLine().getOut().printf("\t%s =  %s (%s)%n", configValue.getName(), value, KeycloakConfigSourceProvider.getConfigSourceDisplayName(configValue.getConfigSourceName()));
    }

    private static String groupProperties(String property) {
        int endIndex = property.indexOf('.');

        if (endIndex == -1) {
            return "";
        }

        return property.substring(0, endIndex);
    }

    private static boolean filterByGroup(String property) {
        return property.startsWith(MicroProfileConfigProvider.NS_KEYCLOAK_PREFIX)
                || property.startsWith(MicroProfileConfigProvider.NS_QUARKUS_PREFIX);
    }

    @Override
    public String getName() {
        return NAME;
    }
}

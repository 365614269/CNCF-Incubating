/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.operator.crds.v2alpha1;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import org.keycloak.operator.Constants;
import org.keycloak.operator.crds.v2alpha1.deployment.Keycloak;
import org.keycloak.operator.crds.v2alpha1.deployment.KeycloakSpec;
import org.keycloak.operator.crds.v2alpha1.deployment.spec.FeatureSpec;
import org.keycloak.operator.crds.v2alpha1.deployment.spec.HttpSpec;

/**
 * @author Vaclav Muzikar <vmuzikar@redhat.com>
 */
public final class CRDUtils {
    private static final String METRICS_ENABLED = "metrics-enabled";
    private static final String HEALTH_ENABLED = "health-enabled";
    private static final String LEGACY_MANAGEMENT_ENABLED = "legacy-observability-interface";

    public static boolean isTlsConfigured(Keycloak keycloakCR) {
        var tlsSecret = keycloakSpecOf(keycloakCR).map(KeycloakSpec::getHttpSpec).map(HttpSpec::getTlsSecret);
        return tlsSecret.isPresent() && !tlsSecret.get().trim().isEmpty();
    }

    public static boolean isJGroupEnabled(Keycloak keycloak) {
        // If multi-site or clusterless are present, JGroups is not enabled.
        return CRDUtils.keycloakSpecOf(keycloak)
                .map(KeycloakSpec::getFeatureSpec)
                .map(FeatureSpec::getEnabledFeatures)
                .filter(features -> features.contains("multi-site") || features.contains("clusterless"))
                .isEmpty();
    }

    public static boolean isManagementEndpointEnabled(Keycloak keycloak) {
        Map<String, String> options = new HashMap<>();
        // add default options
        Constants.DEFAULT_DIST_CONFIG_LIST
                .forEach(valueOrSecret -> options.put(valueOrSecret.getName(), valueOrSecret.getValue()));
        // overwrite the configured ones
        keycloakSpecOf(keycloak)
                .map(KeycloakSpec::getAdditionalOptions)
                .stream()
                .flatMap(Collection::stream)
                .forEach(valueOrSecret -> options.put(valueOrSecret.getName(), valueOrSecret.getValue()));

        // Legacy management enabled
        if (Boolean.parseBoolean(options.get(LEGACY_MANAGEMENT_ENABLED))) {
            return false;
        }

        // Only metrics and health use the management endpoint.
        return Stream.of(METRICS_ENABLED, HEALTH_ENABLED)
                .map(options::get)
                .filter(Objects::nonNull)
                .anyMatch(Boolean::parseBoolean);
    }

    public static Optional<KeycloakSpec> keycloakSpecOf(Keycloak keycloak) {
        return Optional.ofNullable(keycloak)
                .map(Keycloak::getSpec);
    }

}

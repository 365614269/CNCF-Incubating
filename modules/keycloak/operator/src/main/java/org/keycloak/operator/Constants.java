/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.operator;

import org.keycloak.operator.crds.v2alpha1.deployment.ValueOrSecret;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class Constants {
    public static final String CRDS_GROUP = "k8s.keycloak.org";
    public static final String CRDS_VERSION = "v2alpha1";
    public static final String SHORT_NAME = "kc";
    public static final String NAME = "keycloak";
    public static final String PLURAL_NAME = "keycloaks";
    public static final String INSTANCE_LABEL = "app.kubernetes.io/instance";
    public static final String MANAGED_BY_LABEL = "app.kubernetes.io/managed-by";
    public static final String MANAGED_BY_VALUE = "keycloak-operator";
    public static final String COMPONENT_LABEL = "app.kubernetes.io/component";
    public static final String KEYCLOAK_COMPONENT_LABEL = "operator.keycloak.org/component";
    public static final String KEYCLOAK_WATCHED_SECRET_HASH_ANNOTATION = "operator.keycloak.org/watched-secret-hash";
    public static final String KEYCLOAK_WATCHING_ANNOTATION = "operator.keycloak.org/watching-secrets";
    public static final String KEYCLOAK_MISSING_SECRETS_ANNOTATION = "operator.keycloak.org/missing-secrets";
    public static final String KEYCLOAK_MIGRATING_ANNOTATION = "operator.keycloak.org/migrating";

    public static final String DEFAULT_LABELS_AS_STRING = "app=keycloak,app.kubernetes.io/managed-by=keycloak-operator";

    public static final Map<String, String> DEFAULT_LABELS = Collections
            .unmodifiableMap(Stream.of(DEFAULT_LABELS_AS_STRING.split(",")).map(s -> s.split("="))
                    .collect(Collectors.toMap(e -> e[0], e -> e[1], (u1, u2) -> u1, TreeMap::new)));

    public static final List<ValueOrSecret> DEFAULT_DIST_CONFIG_LIST = List.of(
            new ValueOrSecret("health-enabled", "true"),
            new ValueOrSecret("cache", "ispn"),
            new ValueOrSecret("cache-stack", "kubernetes"),
            new ValueOrSecret("proxy", "passthrough")
    );


    public static final Integer KEYCLOAK_HTTP_PORT = 8080;
    public static final Integer KEYCLOAK_HTTPS_PORT = 8443;
    public static final String KEYCLOAK_HTTP_PORT_NAME = "http";
    public static final String KEYCLOAK_HTTPS_PORT_NAME = "https";
    public static final String KEYCLOAK_SERVICE_PROTOCOL = "TCP";
    public static final String KEYCLOAK_SERVICE_SUFFIX = "-service";
    public static final Integer KEYCLOAK_DISCOVERY_SERVICE_PORT = 7800;
    public static final String KEYCLOAK_DISCOVERY_SERVICE_SUFFIX = "-discovery";

    public static final String KEYCLOAK_INGRESS_SUFFIX = "-ingress";

    public static final String INSECURE_DISABLE = "INSECURE-DISABLE";
    public static final String CERTIFICATES_FOLDER = "/mnt/certificates";

    public static String KEYCLOAK_HTTP_RELATIVE_PATH_KEY = "http-relative-path";
}

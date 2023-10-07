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
package org.keycloak.operator.controllers;

import io.fabric8.kubernetes.api.model.EnvVar;
import io.fabric8.kubernetes.api.model.EnvVarBuilder;
import io.fabric8.kubernetes.api.model.EnvVarSource;
import io.fabric8.kubernetes.api.model.EnvVarSourceBuilder;
import io.fabric8.kubernetes.api.model.PodSpec;
import io.fabric8.kubernetes.api.model.PodSpecFluent.ContainersNested;
import io.fabric8.kubernetes.api.model.PodTemplateSpec;
import io.fabric8.kubernetes.api.model.PodTemplateSpecFluent.SpecNested;
import io.fabric8.kubernetes.api.model.SecretKeySelector;
import io.fabric8.kubernetes.api.model.VolumeBuilder;
import io.fabric8.kubernetes.api.model.VolumeMountBuilder;
import io.fabric8.kubernetes.api.model.apps.StatefulSet;
import io.fabric8.kubernetes.api.model.apps.StatefulSetBuilder;
import io.fabric8.kubernetes.api.model.apps.StatefulSetSpec;
import io.fabric8.kubernetes.api.model.apps.StatefulSetSpecFluent.TemplateNested;
import io.javaoperatorsdk.operator.api.reconciler.Context;
import io.javaoperatorsdk.operator.processing.dependent.kubernetes.CRUDKubernetesDependentResource;
import io.javaoperatorsdk.operator.processing.dependent.kubernetes.KubernetesDependent;
import io.quarkus.logging.Log;

import org.keycloak.operator.Config;
import org.keycloak.operator.Constants;
import org.keycloak.operator.Utils;
import org.keycloak.operator.crds.v2alpha1.deployment.Keycloak;
import org.keycloak.operator.crds.v2alpha1.deployment.KeycloakSpec;
import org.keycloak.operator.crds.v2alpha1.deployment.ValueOrSecret;
import org.keycloak.operator.crds.v2alpha1.deployment.spec.UnsupportedSpec;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import jakarta.inject.Inject;

import static org.keycloak.operator.crds.v2alpha1.CRDUtils.isTlsConfigured;

@KubernetesDependent(labelSelector = Constants.DEFAULT_LABELS_AS_STRING)
public class KeycloakDeploymentDependentResource extends CRUDKubernetesDependentResource<StatefulSet, Keycloak> {

    public static final String OPTIMIZED_ARG = "--optimized";

    @Inject
    Config operatorConfig;

    @Inject
    WatchedSecrets watchedSecrets;

    @Inject
    KeycloakDistConfigurator distConfigurator;

    public KeycloakDeploymentDependentResource() {
        super(StatefulSet.class);
    }

    @Override
    public StatefulSet desired(Keycloak primary, Context<Keycloak> context) {
        StatefulSet baseDeployment = createBaseDeployment(primary, context);
        if (isTlsConfigured(primary)) {
            configureTLS(primary, baseDeployment);
        }
        addEnvVarsAndWatchSecrets(baseDeployment, primary);

        StatefulSet existingDeployment = context.getSecondaryResource(StatefulSet.class).orElse(null);
        if (existingDeployment == null) {
            Log.info("No existing Deployment found, using the default");
        }
        else {
            Log.info("Existing Deployment found, handling migration");

            // version 22 changed the match labels, account for older versions
            if (!existingDeployment.isMarkedForDeletion() && !hasExpectedMatchLabels(existingDeployment, primary)) {
                context.getClient().resource(existingDeployment).lockResourceVersion().delete();
                Log.info("Existing Deployment found with old label selector, it will be recreated");
            }

            migrateDeployment(existingDeployment, baseDeployment, context);
        }

        return baseDeployment;
    }

    void configureTLS(Keycloak keycloakCR, StatefulSet deployment) {
        var kcContainer = deployment.getSpec().getTemplate().getSpec().getContainers().get(0);

        var volume = new VolumeBuilder()
                .withName("keycloak-tls-certificates")
                .withNewSecret()
                .withSecretName(keycloakCR.getSpec().getHttpSpec().getTlsSecret())
                .withOptional(false)
                .endSecret()
                .build();

        var volumeMount = new VolumeMountBuilder()
                .withName(volume.getName())
                .withMountPath(Constants.CERTIFICATES_FOLDER)
                .build();

        deployment.getSpec().getTemplate().getSpec().getVolumes().add(0, volume);
        kcContainer.getVolumeMounts().add(0, volumeMount);
    }

    @Override
    protected void onCreated(Keycloak primary, StatefulSet created, Context<Keycloak> context) {
        watchedSecrets.addLabelsToWatchedSecrets(created);
        super.onCreated(primary, created, context);
    }

    @Override
    protected void onUpdated(Keycloak primary, StatefulSet updated, StatefulSet actual, Context<Keycloak> context) {
        watchedSecrets.addLabelsToWatchedSecrets(updated);
        super.onUpdated(primary, updated, actual, context);
    }

    private boolean hasExpectedMatchLabels(StatefulSet statefulSet, Keycloak keycloak) {
        return Optional.ofNullable(statefulSet).map(s -> Utils.allInstanceLabels(keycloak).equals(s.getSpec().getSelector().getMatchLabels())).orElse(true);
    }

    static Optional<PodTemplateSpec> getPodTemplateSpec(Keycloak keycloakCR) {
        return Optional.ofNullable(keycloakCR.getSpec()).map(KeycloakSpec::getUnsupported).map(UnsupportedSpec::getPodTemplate);
    }

    private StatefulSet createBaseDeployment(Keycloak keycloakCR, Context<Keycloak> context) {
        Map<String, String> labels = Utils.allInstanceLabels(keycloakCR);
        if (operatorConfig.keycloak().podLabels() != null) {
            labels.putAll(operatorConfig.keycloak().podLabels());
        }

        /* Create a builder for the statefulset, note that the pod template spec is used as the basis
         * over that some values are forced, others will let the template override, others merge
         */

        StatefulSetBuilder baseDeploymentBuilder = new StatefulSetBuilder()
                .withNewMetadata()
                    .withName(getName(keycloakCR))
                    .withNamespace(keycloakCR.getMetadata().getNamespace())
                    .withLabels(Utils.allInstanceLabels(keycloakCR))
                    .addToAnnotations(Constants.KEYCLOAK_MIGRATING_ANNOTATION, Boolean.FALSE.toString())
                .endMetadata()
                .withNewSpec()
                    .withNewSelector()
                        .withMatchLabels(Utils.allInstanceLabels(keycloakCR))
                    .endSelector()
                    .withNewTemplateLike(getPodTemplateSpec(keycloakCR).orElseGet(PodTemplateSpec::new))
                        .editOrNewMetadata().addToLabels(labels).endMetadata()
                        .editOrNewSpec().withImagePullSecrets(keycloakCR.getSpec().getImagePullSecrets()).endSpec()
                    .endTemplate()
                    .withReplicas(keycloakCR.getSpec().getInstances())
                .endSpec();

        var specBuilder = baseDeploymentBuilder.editSpec().editTemplate().editOrNewSpec();

        if (!specBuilder.hasRestartPolicy()) {
            specBuilder.withRestartPolicy("Always");
        }
        if (!specBuilder.hasTerminationGracePeriodSeconds()) {
            specBuilder.withTerminationGracePeriodSeconds(30L);
        }
        if (!specBuilder.hasDnsPolicy()) {
            specBuilder.withDnsPolicy("ClusterFirst");
        }

        // there isn't currently an editOrNewFirstContainer, so we need to do this manually
        ContainersNested<SpecNested<TemplateNested<io.fabric8.kubernetes.api.model.apps.StatefulSetFluent.SpecNested<StatefulSetBuilder>>>> containerBuilder = null;
        if (specBuilder.buildContainers().isEmpty()) {
            containerBuilder = specBuilder.addNewContainer();
        } else {
            containerBuilder = specBuilder.editFirstContainer();
        }

        containerBuilder.withName("keycloak");

        var customImage = Optional.ofNullable(keycloakCR.getSpec().getImage());
        containerBuilder.withImage(customImage.orElse(operatorConfig.keycloak().image()));

        if (!containerBuilder.hasImagePullPolicy()) {
            containerBuilder.withImagePullPolicy(operatorConfig.keycloak().imagePullPolicy());
        }
        if (Optional.ofNullable(containerBuilder.getArgs()).orElse(List.of()).isEmpty()) {
            containerBuilder.withArgs("--verbose", "start");
        }
        if (customImage.isPresent()) {
            containerBuilder.addToArgs(OPTIMIZED_ARG);
        }

        // probes
        var tlsConfigured = isTlsConfigured(keycloakCR);
        var protocol = !tlsConfigured ? "HTTP" : "HTTPS";
        var kcPort = KeycloakServiceDependentResource.getServicePort(tlsConfigured, keycloakCR);

        // Relative path ends with '/'
        var kcRelativePath = readConfigurationValue(Constants.KEYCLOAK_HTTP_RELATIVE_PATH_KEY, keycloakCR, context)
                .map(path -> !path.endsWith("/") ? path + "/" : path)
                .orElse("/");

        if (!containerBuilder.hasReadinessProbe()) {
            containerBuilder.withNewReadinessProbe()
                .withPeriodSeconds(10)
                .withFailureThreshold(3)
                .withNewHttpGet()
                .withScheme(protocol)
                .withNewPort(kcPort)
                .withPath(kcRelativePath + "health/ready")
                .endHttpGet()
                .endReadinessProbe();
        }
        if (!containerBuilder.hasLivenessProbe()) {
            containerBuilder.withNewLivenessProbe()
                .withPeriodSeconds(10)
                .withFailureThreshold(3)
                .withNewHttpGet()
                .withScheme(protocol)
                .withNewPort(kcPort)
                .withPath(kcRelativePath + "health/live")
                .endHttpGet()
                .endLivenessProbe();
        }
        if (!containerBuilder.hasStartupProbe()) {
            containerBuilder.withNewStartupProbe()
                .withPeriodSeconds(1)
                .withFailureThreshold(600)
                .withNewHttpGet()
                .withScheme(protocol)
                .withNewPort(kcPort)
                .withPath(kcRelativePath + "health/started")
                .endHttpGet()
                .endStartupProbe();
        }

        // add in ports - there's no merging being done here
        StatefulSet baseDeployment = containerBuilder
            .addNewPort()
                .withName(Constants.KEYCLOAK_HTTPS_PORT_NAME)
                .withContainerPort(Constants.KEYCLOAK_HTTPS_PORT)
                .withProtocol(Constants.KEYCLOAK_SERVICE_PROTOCOL)
            .endPort()
            .addNewPort()
                .withName(Constants.KEYCLOAK_HTTP_PORT_NAME)
                .withContainerPort(Constants.KEYCLOAK_HTTP_PORT)
                .withProtocol(Constants.KEYCLOAK_SERVICE_PROTOCOL)
            .endPort()
            .endContainer().endSpec().endTemplate().endSpec().build();

        return baseDeployment;
    }

    private void addEnvVarsAndWatchSecrets(StatefulSet baseDeployment, Keycloak keycloakCR) {
        var firstClasssEnvVars = distConfigurator.configureDistOptions(keycloakCR);

        String adminSecretName = KeycloakAdminSecretDependentResource.getName(keycloakCR);
        var additionalEnvVars = getDefaultAndAdditionalEnvVars(keycloakCR, adminSecretName);

        var env = Optional.ofNullable(baseDeployment.getSpec().getTemplate().getSpec().getContainers().get(0).getEnv()).orElse(List.of());

        // accumulate the env vars in priority order - unsupported, first class, additional
        var envVars = new ArrayList<>(Stream.concat(Stream.concat(env.stream(), firstClasssEnvVars.stream()), additionalEnvVars.stream())
                .collect(Collectors.toMap(EnvVar::getName, Function.identity(), (e1, e2) -> e1, LinkedHashMap::new))
                .values());
        baseDeployment.getSpec().getTemplate().getSpec().getContainers().get(0).setEnv(envVars);

        // watch the secrets used by secret key - we don't currently expect configmaps, optional refs, or watch the initial-admin
        TreeSet<String> serverConfigSecretsNames = envVars.stream().map(EnvVar::getValueFrom).filter(Objects::nonNull)
                .map(EnvVarSource::getSecretKeyRef).filter(Objects::nonNull).map(SecretKeySelector::getName)
                .filter(n -> !n.equals(adminSecretName)).collect(Collectors.toCollection(TreeSet::new));

        Log.infof("Found config secrets names: %s", serverConfigSecretsNames);

        // add secrets from volume mounts (currently just the tls secret)
        if (isTlsConfigured(keycloakCR)) {
            serverConfigSecretsNames.add(keycloakCR.getSpec().getHttpSpec().getTlsSecret());
        }

        if (!serverConfigSecretsNames.isEmpty()) {
            watchedSecrets.annotateDeployment(new ArrayList<>(serverConfigSecretsNames), keycloakCR, baseDeployment);
        }
    }

    private List<EnvVar> getDefaultAndAdditionalEnvVars(Keycloak keycloakCR, String adminSecretName) {
        // default config values
        List<ValueOrSecret> serverConfigsList = new ArrayList<>(Constants.DEFAULT_DIST_CONFIG_LIST);

        // merge with the CR; the values in CR take precedence
        if (keycloakCR.getSpec().getAdditionalOptions() != null) {
            Set<String> inCr = keycloakCR.getSpec().getAdditionalOptions().stream().map(v -> v.getName()).collect(Collectors.toSet());
            serverConfigsList.removeIf(v -> inCr.contains(v.getName()));
            serverConfigsList.addAll(keycloakCR.getSpec().getAdditionalOptions());
        }

        // set env vars
        List<EnvVar> envVars = serverConfigsList.stream()
                .map(v -> {
                    var envBuilder = new EnvVarBuilder().withName(KeycloakDistConfigurator.getKeycloakOptionEnvVarName(v.getName()));
                    var secret = v.getSecret();
                    if (secret != null) {
                        envBuilder.withValueFrom(
                                new EnvVarSourceBuilder().withSecretKeyRef(secret).build());
                    } else {
                        envBuilder.withValue(v.getValue());
                    }
                    return envBuilder.build();
                })
                .collect(Collectors.toList());

        envVars.add(
                new EnvVarBuilder()
                        .withName("KEYCLOAK_ADMIN")
                        .withNewValueFrom()
                        .withNewSecretKeyRef()
                        .withName(adminSecretName)
                        .withKey("username")
                        .withOptional(false)
                        .endSecretKeyRef()
                        .endValueFrom()
                        .build());
        envVars.add(
                new EnvVarBuilder()
                        .withName("KEYCLOAK_ADMIN_PASSWORD")
                        .withNewValueFrom()
                        .withNewSecretKeyRef()
                        .withName(adminSecretName)
                        .withKey("password")
                        .withOptional(false)
                        .endSecretKeyRef()
                        .endValueFrom()
                        .build());

        envVars.add(
                new EnvVarBuilder()
                        .withName("jgroups.dns.query")
                        .withValue(getName(keycloakCR) + Constants.KEYCLOAK_DISCOVERY_SERVICE_SUFFIX +"." + keycloakCR.getMetadata().getNamespace())
                        .build());

        return envVars;
    }

    public static String getName(Keycloak keycloak) {
        return keycloak.getMetadata().getName();
    }

    public void migrateDeployment(StatefulSet previousDeployment, StatefulSet reconciledDeployment, Context<Keycloak> context) {
        var previousContainer = Optional.ofNullable(previousDeployment).map(StatefulSet::getSpec)
                .map(StatefulSetSpec::getTemplate).map(PodTemplateSpec::getSpec).map(PodSpec::getContainers)
                .flatMap(c -> c.stream().findFirst()).orElse(null);
        if (previousContainer == null) {
            return;
        }
        var reconciledContainer = reconciledDeployment.getSpec().getTemplate().getSpec().getContainers().get(0);

        if (!previousContainer.getImage().equals(reconciledContainer.getImage())
                && previousDeployment.getStatus().getReplicas() > 1) {
            // TODO Check if migration is really needed (e.g. based on actual KC version); https://github.com/keycloak/keycloak/issues/10441
            Log.info("Detected changed Keycloak image, assuming Keycloak upgrade. Scaling down the deployment to one instance to perform a safe database migration");
            Log.infof("original image: %s; new image: %s", previousContainer.getImage(), reconciledContainer.getImage());

            reconciledContainer.setImage(previousContainer.getImage());
            reconciledDeployment.getSpec().setReplicas(1);

            reconciledDeployment.getMetadata().getAnnotations().put(Constants.KEYCLOAK_MIGRATING_ANNOTATION, Boolean.TRUE.toString());
        }
    }

    protected Optional<String> readConfigurationValue(String key, Keycloak keycloakCR, Context<Keycloak> context) {
        return Optional.ofNullable(keycloakCR.getSpec()).map(KeycloakSpec::getAdditionalOptions)
                .flatMap(l -> l.stream().filter(sc -> sc.getName().equals(key)).findFirst().map(serverConfigValue -> {
            if (serverConfigValue.getValue() != null) {
                return serverConfigValue.getValue();
            }
            var secretSelector = serverConfigValue.getSecret();
            if (secretSelector == null) {
                throw new IllegalStateException("Secret " + serverConfigValue.getName() + " not defined");
            }
            var secret = context.getClient().secrets().inNamespace(keycloakCR.getMetadata().getNamespace()).withName(secretSelector.getName()).get();
            if (secret == null) {
                throw new IllegalStateException("Secret " + secretSelector.getName() + " not found in cluster");
            }
            if (secret.getData().containsKey(secretSelector.getKey())) {
                return new String(Base64.getDecoder().decode(secret.getData().get(secretSelector.getKey())), StandardCharsets.UTF_8);
            }
            throw new IllegalStateException("Secret " + secretSelector.getName() + " doesn't contain the expected key " + secretSelector.getKey());
        }));
    }

}

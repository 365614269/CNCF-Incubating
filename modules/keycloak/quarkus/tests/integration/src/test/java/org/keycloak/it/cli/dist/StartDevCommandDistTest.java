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

package org.keycloak.it.cli.dist;

import io.quarkus.test.junit.main.Launch;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.keycloak.it.junit5.extension.CLIResult;
import org.keycloak.it.junit5.extension.DistributionTest;
import org.keycloak.it.junit5.extension.DryRun;
import org.keycloak.it.junit5.extension.RawDistOnly;
import org.keycloak.it.utils.KeycloakDistribution;
import org.keycloak.it.utils.RawKeycloakDistribution;

import java.io.File;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertTrue;

@DistributionTest
@RawDistOnly(reason = "Containers are immutable")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Tag(DistributionTest.WIN)
public class StartDevCommandDistTest {

    @DryRun
    @Test
    @Launch({ "start-dev" })
    void testDevModeWarning(CLIResult cliResult) {
        cliResult.assertStartedDevMode();
    }

    @DryRun
    @Test
    @Launch({ "start-dev", "--db=dev-mem" })
    void testBuildPropertyAvailable(CLIResult cliResult) {
        cliResult.assertStartedDevMode();
    }

    @Test
    @Launch({ "start-dev", "--debug", "--features=passkeys:v1" })
    void testStartDevShouldStartTwoJVMs(CLIResult cliResult) {
        cliResult.assertMessageWasShownExactlyNumberOfTimes("Listening for transport dt_socket at address:", 2);
        cliResult.assertStartedDevMode();
        cliResult.assertMessage("passkeys");
    }

    @DryRun
    @Test
    @Launch({ "build", "--debug", "--db=dev-file" })
    void testBuildMustNotRunTwoJVMs(CLIResult cliResult) {
        cliResult.assertMessageWasShownExactlyNumberOfTimes("Listening for transport dt_socket at address:", 1);
        cliResult.assertBuild();
    }

    @DryRun
    @Test
    @Launch({ "start-dev", "--verbose" })
    void testVerboseAfterCommand(CLIResult cliResult) {
        cliResult.assertStartedDevMode();
    }

    @Test
    @DisabledOnOs(value = { OS.LINUX, OS.MAC }, disabledReason = "A drive letter in URI can cause a problem.")
    void testConfigKeystoreAbsolutePath(KeycloakDistribution dist) {
        CLIResult cliResult = dist.run("start-dev", "--config-keystore=" + Paths.get("src/test/resources/keystore").toAbsolutePath().normalize(),
                "--config-keystore-password=secret");

        cliResult.assertMessage("DEBUG [org.hibernate");
        cliResult.assertMessage("DEBUG [org.keycloak");
        cliResult.assertMessage("Listening on:");
        cliResult.assertStartedDevMode();
    }

    @DryRun
    @Test
    void testStartDevThenImportRebuild(KeycloakDistribution dist) throws Exception {
        RawKeycloakDistribution rawDist = dist.unwrap(RawKeycloakDistribution.class);
        CLIResult result = rawDist.run("start-dev");
        assertTrue(result.getErrorOutput().isEmpty(), result.getErrorOutput());

        File target = new File("./target");

        // feature change should trigger a build
        result = rawDist.run("--profile=dev", "export", "--features=docker", "--dir=" + target.getAbsolutePath());
        result.assertMessage("Updating the configuration and installing your custom providers, if any. Please wait.");
    }

}

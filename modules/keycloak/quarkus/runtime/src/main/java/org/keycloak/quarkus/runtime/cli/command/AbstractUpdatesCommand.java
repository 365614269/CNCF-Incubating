/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
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

import java.io.File;
import java.util.List;
import java.util.function.Predicate;

import org.keycloak.config.OptionCategory;
import org.keycloak.quarkus.runtime.cli.PropertyException;
import org.keycloak.quarkus.runtime.compatibility.CompatibilityManager;
import org.keycloak.quarkus.runtime.compatibility.CompatibilityManagerImpl;
import picocli.CommandLine;

public abstract class AbstractUpdatesCommand extends AbstractCommand implements Runnable {

    protected final CompatibilityManager compatibilityManager = new CompatibilityManagerImpl();

    @CommandLine.Mixin
    HelpAllMixin helpAllMixin;

    @CommandLine.Mixin
    OptimizedMixin optimizedMixin;

    @Override
    public List<OptionCategory> getOptionCategories() {
        return super.getOptionCategories().stream()
                .filter(Predicate.not(OptionCategory.EXPORT::equals))
                .filter(Predicate.not(OptionCategory.IMPORT::equals))
                .toList();
    }

    static void validateOptionIsPresent(String value, String option) {
        if (value == null || value.isBlank()) {
            throw new PropertyException("Missing required argument: " + option);
        }
    }

    static void validateFileIsNotDirectory(File file, String option) {
        if (file.isDirectory()) {
            throw new PropertyException("Incorrect argument %s. Path '%s' is not a valid file.".formatted(option, file.getAbsolutePath()));
        }
    }

    void printOut(String message) {
        var cmd = getCommandLine();
        if (cmd.isPresent()) {
            cmd.get().getOut().println(message);
        } else {
            System.out.println(message);
        }
    }

    void printError(String message) {
        var cmd = getCommandLine();
        if (cmd.isPresent()) {
            var colorScheme = cmd.get().getColorScheme();
            cmd.get().getErr().println(colorScheme.errorText(message));
        } else {
            System.err.println(message);
        }
    }

    void printPreviewWarning() {
        printError("Warning! This command is preview and is not recommended for use in production. It may change or be removed at a future release.");
    }

}

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

package org.keycloak.quarkus.deployment;

import static org.keycloak.config.StorageOptions.STORAGE;
import static org.keycloak.quarkus.runtime.configuration.Configuration.getOptionalValue;
import static org.keycloak.quarkus.runtime.configuration.MicroProfileConfigProvider.NS_KEYCLOAK_PREFIX;

import java.util.Optional;
import java.util.function.BooleanSupplier;
import org.keycloak.config.StorageOptions;

/***
 * Checks if JPA is enabled either for the legacy or the new store.
 *
 * Returns true if the legacy store is used or the new store is used with storage==jpa
 */
public class IsJpaStoreEnabled implements BooleanSupplier {

    @Override
    public boolean getAsBoolean() {
        Optional<String> storage = getOptionalValue(NS_KEYCLOAK_PREFIX.concat(STORAGE.getKey()));

        if (storage.isEmpty()) {
            // legacy store
            return true;
        }

        return StorageOptions.StorageType.jpa.name().equals(storage.orElse(null));
    }

}

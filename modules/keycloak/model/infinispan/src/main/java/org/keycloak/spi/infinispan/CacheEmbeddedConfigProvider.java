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

package org.keycloak.spi.infinispan;

import org.infinispan.configuration.parsing.ConfigurationBuilderHolder;
import org.infinispan.manager.EmbeddedCacheManager;
import org.keycloak.provider.Provider;

/**
 * A provider to create the {@link ConfigurationBuilderHolder} to configure the {@link EmbeddedCacheManager}.
 */
public interface CacheEmbeddedConfigProvider extends Provider {

    /**
     * The {@link ConfigurationBuilderHolder} whit the {@link EmbeddedCacheManager} configuration. It must not be
     * {@code null}.
     *
     * @return The {@link ConfigurationBuilderHolder} whit the {@link EmbeddedCacheManager} configuration.
     */
    ConfigurationBuilderHolder configuration();

    @Override
    default void close() {
        //no-op
    }
}

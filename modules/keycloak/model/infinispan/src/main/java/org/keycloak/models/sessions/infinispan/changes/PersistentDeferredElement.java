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

package org.keycloak.models.sessions.infinispan.changes;

import org.keycloak.models.sessions.infinispan.entities.SessionEntity;

import java.util.Map;

/**
 * Capture information for a deferred update of the session stores.
 *
 * @author Alexander Schwartz
 */
public class PersistentDeferredElement<K, V extends SessionEntity> {
    private final Map.Entry<K, SessionUpdatesList<V>> entry;
    private final MergedUpdate<V> merged;

    public PersistentDeferredElement(Map.Entry<K, SessionUpdatesList<V>> entry, MergedUpdate<V> merged) {
        this.entry = entry;
        this.merged = merged;
    }

    public Map.Entry<K, SessionUpdatesList<V>> getEntry() {
        return entry;
    }

    public MergedUpdate<V> getMerged() {
        return merged;
    }
}

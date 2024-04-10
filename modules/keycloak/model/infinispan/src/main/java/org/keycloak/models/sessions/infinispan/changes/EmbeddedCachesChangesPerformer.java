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

import org.infinispan.Cache;
import org.infinispan.context.Flag;
import org.jboss.logging.Logger;
import org.keycloak.connections.infinispan.InfinispanUtil;
import org.keycloak.models.sessions.infinispan.CacheDecorators;
import org.keycloak.models.sessions.infinispan.entities.SessionEntity;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;

public class EmbeddedCachesChangesPerformer<K, V extends SessionEntity> implements SessionChangesPerformer<K, V> {

    private static final Logger LOG = Logger.getLogger(EmbeddedCachesChangesPerformer.class);
    private final Cache<K, SessionEntityWrapper<V>> cache;
    private final SerializeExecutionsByKey<K> serializer;
    private final List<Runnable> changes = new LinkedList<>();

    public EmbeddedCachesChangesPerformer(Cache<K, SessionEntityWrapper<V>> cache, SerializeExecutionsByKey<K> serializer) {
        this.cache = cache;
        this.serializer = serializer;
    }

    private void runOperationInCluster(K key, MergedUpdate<V> task,  SessionEntityWrapper<V> sessionWrapper) {
        V session = sessionWrapper.getEntity();
        SessionUpdateTask.CacheOperation operation = task.getOperation(session);

        // Don't need to run update of underlying entity. Local updates were already run
        //task.runUpdate(session);

        switch (operation) {
            case REMOVE:
                // Just remove it
                CacheDecorators.skipCacheStoreIfRemoteCacheIsEnabled(cache)
                        .withFlags(Flag.IGNORE_RETURN_VALUES)
                        .remove(key);
                break;
            case ADD:
                CacheDecorators.skipCacheStoreIfRemoteCacheIsEnabled(cache)
                        .withFlags(Flag.IGNORE_RETURN_VALUES)
                        .put(key, sessionWrapper, task.getLifespanMs(), TimeUnit.MILLISECONDS, task.getMaxIdleTimeMs(), TimeUnit.MILLISECONDS);

                LOG.tracef("Added entity '%s' to the cache '%s' . Lifespan: %d ms, MaxIdle: %d ms", key, cache.getName(), task.getLifespanMs(), task.getMaxIdleTimeMs());
                break;
            case ADD_IF_ABSENT:
                SessionEntityWrapper<V> existing = CacheDecorators.skipCacheStoreIfRemoteCacheIsEnabled(cache).putIfAbsent(key, sessionWrapper, task.getLifespanMs(), TimeUnit.MILLISECONDS, task.getMaxIdleTimeMs(), TimeUnit.MILLISECONDS);
                if (existing != null) {
                    LOG.debugf("Existing entity in cache for key: %s . Will update it", key);

                    // Apply updates on the existing entity and replace it
                    task.runUpdate(existing.getEntity());

                    replace(key, task, existing, task.getLifespanMs(), task.getMaxIdleTimeMs());
                } else {
                    LOG.tracef("Add_if_absent successfully called for entity '%s' to the cache '%s' . Lifespan: %d ms, MaxIdle: %d ms", key, cache.getName(), task.getLifespanMs(), task.getMaxIdleTimeMs());
                }
                break;
            case REPLACE:
                replace(key, task, sessionWrapper, task.getLifespanMs(), task.getMaxIdleTimeMs());
                break;
            default:
                throw new IllegalStateException("Unsupported state " +  operation);
        }

    }

    private void replace(K key, MergedUpdate<V> task, SessionEntityWrapper<V> oldVersionEntity, long lifespanMs, long maxIdleTimeMs) {
        serializer.runSerialized(key, () -> {
            SessionEntityWrapper<V> oldVersion = oldVersionEntity;
            boolean replaced = false;
            int iteration = 0;
            V session = oldVersion.getEntity();

            while (!replaced && iteration < InfinispanUtil.MAXIMUM_REPLACE_RETRIES) {
                iteration++;

                SessionEntityWrapper<V> newVersionEntity = generateNewVersionAndWrapEntity(session, oldVersion.getLocalMetadata());

                // Atomic cluster-aware replace
                replaced = CacheDecorators.skipCacheStoreIfRemoteCacheIsEnabled(cache).replace(key, oldVersion, newVersionEntity, lifespanMs, TimeUnit.MILLISECONDS, maxIdleTimeMs, TimeUnit.MILLISECONDS);

                // Replace fail. Need to load latest entity from cache, apply updates again and try to replace in cache again
                if (!replaced) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debugf("Replace failed for entity: %s, old version %s, new version %s. Will try again", key, oldVersion.getVersion(), newVersionEntity.getVersion());
                    }
                    backoff(iteration);

                    oldVersion = cache.get(key);

                    if (oldVersion == null) {
                        LOG.debugf("Entity %s not found. Maybe removed in the meantime. Replace task will be ignored", key);
                        return;
                    }

                    session = oldVersion.getEntity();

                    task.runUpdate(session);
                } else {
                    if (LOG.isTraceEnabled()) {
                        LOG.tracef("Replace SUCCESS for entity: %s . old version: %s, new version: %s, Lifespan: %d ms, MaxIdle: %d ms", key, oldVersion.getVersion(), newVersionEntity.getVersion(), task.getLifespanMs(), task.getMaxIdleTimeMs());
                    }
                }
            }

            if (!replaced) {
                LOG.warnf("Failed to replace entity '%s' in cache '%s'", key, cache.getName());
            }
        });
    }

    /**
     * Wait a random amount of time to avoid a conflict with other concurrent actors on the next attempt.
     */
    private static void backoff(int iteration) {
        try {
            Thread.sleep(new Random().nextInt(iteration));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
    }

    private SessionEntityWrapper<V> generateNewVersionAndWrapEntity(V entity, Map<String, String> localMetadata) {
        return new SessionEntityWrapper<>(localMetadata, entity);
    }

    @Override
    public void registerChange(Map.Entry<K, SessionUpdatesList<V>> entry, MergedUpdate<V> merged) {
        changes.add(() -> runOperationInCluster(entry.getKey(), merged, entry.getValue().getEntityWrapper()));
    }

    @Override
    public void applyChanges() {
        changes.forEach(Runnable::run);
    }
}

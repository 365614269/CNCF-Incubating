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

package org.keycloak.models.map.storage.jpa;

import org.hibernate.boot.Metadata;
import org.hibernate.dialect.CockroachDialect;
import org.hibernate.engine.OptimisticLockStyle;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.event.service.spi.EventListenerRegistry;
import org.hibernate.event.spi.EventType;
import org.hibernate.integrator.spi.Integrator;
import org.hibernate.mapping.RootClass;
import org.hibernate.service.spi.SessionFactoryServiceRegistry;
import org.keycloak.models.map.storage.jpa.hibernate.listeners.JpaAutoFlushListener;
import org.keycloak.models.map.storage.jpa.hibernate.listeners.JpaEntityVersionListener;
import org.keycloak.models.map.storage.jpa.hibernate.listeners.JpaOptimisticLockingListener;

/**
 * Adding listeners to Hibernate's entity manager for the JPA Map store.
 */
public class EventListenerIntegrator implements Integrator {

    @Override
    public void integrate(Metadata metadata, SessionFactoryImplementor sessionFactoryImplementor,
            SessionFactoryServiceRegistry sessionFactoryServiceRegistry) {
        final EventListenerRegistry eventListenerRegistry =
                sessionFactoryServiceRegistry.getService(EventListenerRegistry.class);

        if (metadata.getDatabase().getDialect() instanceof CockroachDialect) {
            // CockroachDB will always use serializable transactions, therefore no optimistic locking is necessary
            metadata.getEntityBindings().forEach(persistentClass -> {
                if (persistentClass instanceof RootClass) {
                    RootClass root = (RootClass) persistentClass;
                    root.setOptimisticLockStyle(OptimisticLockStyle.NONE);
                    root.setVersion(null);
                    root.setDeclaredVersion(null);
                }
            });
            // If the version column should be updated with an incrementing number on each change in the future,
            // implement a listener similar to JpaOptimisticLockingListener to increment it.
        } else {
            eventListenerRegistry.appendListeners(EventType.PRE_INSERT, JpaOptimisticLockingListener.INSTANCE);
            eventListenerRegistry.appendListeners(EventType.PRE_UPDATE, JpaOptimisticLockingListener.INSTANCE);
            eventListenerRegistry.appendListeners(EventType.PRE_DELETE, JpaOptimisticLockingListener.INSTANCE);
        }

        eventListenerRegistry.appendListeners(EventType.PRE_INSERT, JpaEntityVersionListener.INSTANCE);
        eventListenerRegistry.appendListeners(EventType.PRE_UPDATE, JpaEntityVersionListener.INSTANCE);
        eventListenerRegistry.appendListeners(EventType.PRE_DELETE, JpaEntityVersionListener.INSTANCE);

        // replace auto-flush listener
        eventListenerRegistry.setListeners(EventType.AUTO_FLUSH, JpaAutoFlushListener.INSTANCE);
    }

    @Override
    public void disintegrate(SessionFactoryImplementor sessionFactoryImplementor,
            SessionFactoryServiceRegistry sessionFactoryServiceRegistry) {

    }
}

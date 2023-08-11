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
package org.keycloak.models.map.storage.jpa.event.auth;

import jakarta.persistence.EntityManager;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Selection;

import org.keycloak.events.Event;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.map.events.MapAuthEventEntity;
import org.keycloak.models.map.storage.MapStorage;
import org.keycloak.models.map.storage.jpa.JpaMapStorage;
import org.keycloak.models.map.storage.jpa.JpaModelCriteriaBuilder;
import org.keycloak.models.map.storage.jpa.JpaRootEntity;
import org.keycloak.models.map.storage.jpa.event.auth.entity.JpaAuthEventEntity;

import static org.keycloak.models.map.storage.jpa.Constants.CURRENT_SCHEMA_VERSION_AUTH_EVENT;

/**
 * A {@link MapStorage} implementation for auth event entities.
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class JpaAuthEventMapStorage extends JpaMapStorage<JpaAuthEventEntity, MapAuthEventEntity, Event> {

    public JpaAuthEventMapStorage(KeycloakSession session, final EntityManager em) {
        super(session, JpaAuthEventEntity.class, Event.class, em);
    }

    @Override
    protected Selection<? extends JpaAuthEventEntity> selectCbConstruct(CriteriaBuilder cb, Root<JpaAuthEventEntity> root) {
        return root;
    }

    @Override
    protected void setEntityVersion(JpaRootEntity entity) {
        entity.setEntityVersion(CURRENT_SCHEMA_VERSION_AUTH_EVENT);
    }

    @Override
    protected JpaModelCriteriaBuilder createJpaModelCriteriaBuilder() {
        return new JpaAuthEventModelCriteriaBuilder();
    }

    @Override
    protected MapAuthEventEntity mapToEntityDelegate(JpaAuthEventEntity original) {
        return original;
    }
}

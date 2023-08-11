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
package org.keycloak.models.map.storage.jpa.client;

import jakarta.persistence.EntityManager;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Selection;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.map.client.MapClientEntity;
import org.keycloak.models.map.client.MapClientEntityDelegate;
import org.keycloak.models.map.storage.jpa.client.entity.JpaClientEntity;
import static org.keycloak.models.map.storage.jpa.Constants.CURRENT_SCHEMA_VERSION_CLIENT;
import org.keycloak.models.map.storage.jpa.JpaMapStorage;
import org.keycloak.models.map.storage.jpa.JpaModelCriteriaBuilder;
import org.keycloak.models.map.storage.jpa.JpaRootEntity;
import org.keycloak.models.map.storage.jpa.client.delegate.JpaClientDelegateProvider;

public class JpaClientMapStorage extends JpaMapStorage<JpaClientEntity, MapClientEntity, ClientModel> {

    @SuppressWarnings("unchecked")
    public JpaClientMapStorage(KeycloakSession session, EntityManager em) {
        super(session, JpaClientEntity.class, ClientModel.class, em);
    }

    @Override
    public Selection<JpaClientEntity> selectCbConstruct(CriteriaBuilder cb, Root<JpaClientEntity> root) {
        return cb.construct(JpaClientEntity.class, 
            root.get("id"), 
            root.get("version"),
            root.get("entityVersion"), 
            root.get("realmId"), 
            root.get("clientId"), 
            root.get("protocol"), 
            root.get("enabled")
        );
    }

    @Override
    public void setEntityVersion(JpaRootEntity entity) {
        entity.setEntityVersion(CURRENT_SCHEMA_VERSION_CLIENT);
    }

    @Override
    public JpaModelCriteriaBuilder createJpaModelCriteriaBuilder() {
        return new JpaClientModelCriteriaBuilder();
    }

    @Override
    protected MapClientEntity mapToEntityDelegate(JpaClientEntity original) {
        return new MapClientEntityDelegate(new JpaClientDelegateProvider(original, em));
    }
}

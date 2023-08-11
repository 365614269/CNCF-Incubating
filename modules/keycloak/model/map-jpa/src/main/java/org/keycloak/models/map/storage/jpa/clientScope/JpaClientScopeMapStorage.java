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
package org.keycloak.models.map.storage.jpa.clientScope;

import jakarta.persistence.EntityManager;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Selection;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.map.clientscope.MapClientScopeEntity;
import org.keycloak.models.map.clientscope.MapClientScopeEntityDelegate;
import static org.keycloak.models.map.storage.jpa.Constants.CURRENT_SCHEMA_VERSION_CLIENT_SCOPE;
import org.keycloak.models.map.storage.jpa.JpaMapStorage;
import org.keycloak.models.map.storage.jpa.JpaModelCriteriaBuilder;
import org.keycloak.models.map.storage.jpa.JpaRootEntity;
import org.keycloak.models.map.storage.jpa.clientScope.delegate.JpaClientScopeDelegateProvider;
import org.keycloak.models.map.storage.jpa.clientScope.entity.JpaClientScopeEntity;

public class JpaClientScopeMapStorage extends JpaMapStorage<JpaClientScopeEntity, MapClientScopeEntity, ClientScopeModel> {

    @SuppressWarnings("unchecked")
    public JpaClientScopeMapStorage(KeycloakSession session, EntityManager em) {
        super(session, JpaClientScopeEntity.class, ClientScopeModel.class, em);
    }

    @Override
    protected Selection<JpaClientScopeEntity> selectCbConstruct(CriteriaBuilder cb, Root<JpaClientScopeEntity> root) {
        return cb.construct(JpaClientScopeEntity.class,
            root.get("id"),
            root.get("version"),
            root.get("entityVersion"),
            root.get("realmId"),
            root.get("name"));
    }

    @Override
    public void setEntityVersion(JpaRootEntity entity) {
        entity.setEntityVersion(CURRENT_SCHEMA_VERSION_CLIENT_SCOPE);
    }

    @Override
    public JpaModelCriteriaBuilder createJpaModelCriteriaBuilder() {
        return new JpaClientScopeModelCriteriaBuilder();
    }

    @Override
    protected MapClientScopeEntity mapToEntityDelegate(JpaClientScopeEntity original) {
        return new MapClientScopeEntityDelegate(new JpaClientScopeDelegateProvider(original, em));
    }
}

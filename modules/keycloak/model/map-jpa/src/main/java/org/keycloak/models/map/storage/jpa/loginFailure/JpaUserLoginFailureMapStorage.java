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
package org.keycloak.models.map.storage.jpa.loginFailure;

import jakarta.persistence.EntityManager;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Selection;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserLoginFailureModel;
import org.keycloak.models.map.loginFailure.MapUserLoginFailureEntity;
import org.keycloak.models.map.loginFailure.MapUserLoginFailureEntityDelegate;
import org.keycloak.models.map.storage.jpa.JpaMapStorage;
import org.keycloak.models.map.storage.jpa.JpaModelCriteriaBuilder;
import org.keycloak.models.map.storage.jpa.JpaRootEntity;
import org.keycloak.models.map.storage.jpa.loginFailure.delegate.JpaUserLoginFailureDelegateProvider;
import org.keycloak.models.map.storage.jpa.loginFailure.entity.JpaUserLoginFailureEntity;

import static org.keycloak.models.map.storage.jpa.Constants.CURRENT_SCHEMA_VERSION_USER_LOGIN_FAILURE;

/**
 * A {@link JpaMapStorage} implementation for user login failure entities.
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class JpaUserLoginFailureMapStorage extends JpaMapStorage<JpaUserLoginFailureEntity, MapUserLoginFailureEntity, UserLoginFailureModel> {

    @SuppressWarnings("unchecked")
    public JpaUserLoginFailureMapStorage(KeycloakSession session, EntityManager em) {
        super(session, JpaUserLoginFailureEntity.class, UserLoginFailureModel.class, em);
    }

    @Override
    public Selection<JpaUserLoginFailureEntity> selectCbConstruct(CriteriaBuilder cb, Root<JpaUserLoginFailureEntity> root) {
        return cb.construct(JpaUserLoginFailureEntity.class,
                root.get("id"),
                root.get("version"),
                root.get("entityVersion"),
                root.get("realmId"),
                root.get("userId")
        );
    }

    @Override
    public void setEntityVersion(JpaRootEntity entity) {
        entity.setEntityVersion(CURRENT_SCHEMA_VERSION_USER_LOGIN_FAILURE);
    }

    @Override
    public JpaModelCriteriaBuilder createJpaModelCriteriaBuilder() {
        return new JpaUserLoginFailureModelCriteriaBuilder();
    }

    @Override
    protected MapUserLoginFailureEntity mapToEntityDelegate(JpaUserLoginFailureEntity original) {
        return new MapUserLoginFailureEntityDelegate(new JpaUserLoginFailureDelegateProvider(original, em));
    }
}